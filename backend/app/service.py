"""Upload processing: PCAP file -> packets -> flows -> alerts -> (optional) AI/email -> DB."""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import tempfile
from typing import Any, BinaryIO, Dict, List, Tuple

from sqlalchemy.orm import Session

from backend.app.ai_agent import investigate_alert

from backend.app.capture import PcapReadError, read_pcap
from backend.app.detection import run_detection
from backend.app.models import AlertRow, Upload
from backend.app.pipeline import enrich_alerts

log = logging.getLogger("packetiq.service")

# Classic pcap (both byte orders, us/ns timestamps) and pcapng section header block.
PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"), bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"), bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("0a0d0d0a"),
}
ALLOWED_EXTENSIONS = (".pcap", ".pcapng", ".cap")
CHUNK = 1024 * 1024


class UploadError(Exception):
    """Client-facing upload problem. `status` is the HTTP status to return."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def safe_filename(name: str) -> str:
    base = os.path.basename((name or "").replace("\\", "/")).strip()
    return "".join(c for c in base if c.isprintable() and c not in '<>"|?*')[:200] or "upload.pcap"


def validate_name(filename: str) -> None:
    if not filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise UploadError(415, "Unsupported file type. Upload a .pcap or .pcapng file.")


def spool_to_temp(stream: BinaryIO, max_bytes: int) -> tuple[str, int]:
    """Copy the upload to a temp file with a hard size cap; check the magic bytes.

    Returns (temp_path, size). Caller must delete the file. On error the file is removed.
    """
    fd, path = tempfile.mkstemp(prefix="packetiq_", suffix=".pcap")
    size = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                if size == 0 and chunk[:4] not in PCAP_MAGICS:
                    raise UploadError(415, "File content is not a PCAP/PCAPNG capture.")
                size += len(chunk)
                if size > max_bytes:
                    raise UploadError(413, f"File too large. Limit is {max_bytes // (1024 * 1024)} MB.")
                out.write(chunk)
        if size == 0:
            raise UploadError(400, "Uploaded file is empty.")
        return path, size
    except BaseException:
        remove_quietly(path)
        raise


def remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def process_pcap(db: Session, path: str, filename: str, size: int,
                 use_ai: bool, notify: bool, max_ai_alerts: int) -> Upload:
    """Run the full pipeline on a saved PCAP and persist the results."""
    try:
        records = read_pcap(path)
    except PcapReadError as exc:
        raise UploadError(422, f"Could not parse capture: {exc}") from None
    except Exception as exc:  # defensive: never leak a traceback to the client
        log.error("Unexpected parse failure: %s", type(exc).__name__)
        raise UploadError(422, "Could not parse capture.") from None
    if not records:
        raise UploadError(422, "Capture contains no packets.")

    engine = run_detection(records)
    alerts: List[Dict[str, Any]] = [a.to_dict() for a in engine.alerts]
    results = enrich_alerts(alerts, use_ai=use_ai, notify=notify, max_alerts=max_ai_alerts)

    upload = Upload(filename=filename, size_bytes=size, packet_count=len(records),
                    flow_count=len(engine.flows.flows), alert_count=len(results),
                    ai_requested=use_ai)
    for r in results:
        a = r["alert"]
        upload.alerts.append(AlertRow(
            rule_id=a["rule_id"], rule_name=a["rule_name"], severity=a["severity"],
            timestamp_iso=a.get("timestamp_iso"), src_ip=a.get("src_ip"), dst_ip=a.get("dst_ip"),
            summary=a["summary"], evidence=a.get("evidence") or {},
            ai_status=r.get("investigation_status", "skipped"),
            ai_error=r.get("investigation_error"), ai_report=r.get("report"),
            notified=bool(r.get("notified")),
        ))
    db.add(upload)
    db.commit()
    return upload


# ------------------------------------------------------- single-alert actions
def alert_input(row: AlertRow) -> Dict[str, Any]:
    """Rebuild the detection alert from a stored row, in the shape ai_agent expects."""
    return {
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "severity": row.severity,
        "timestamp_iso": row.timestamp_iso,
        "src_ip": row.src_ip,
        "dst_ip": row.dst_ip,
        "summary": row.summary,
        "evidence": row.evidence or {},
    }


def investigate_stored(db: Session, row: AlertRow) -> AlertRow:
    """Investigate one stored alert and save the outcome on that row.

    Only this alert goes to the provider. A failure is saved as the status and error,
    the same way the upload path records it, and the alert itself is kept.
    """
    result = investigate_alert(alert_input(row))
    row.ai_status = result.get("investigation_status", "failed")
    row.ai_error = result.get("investigation_error")
    row.ai_report = result.get("report")
    db.commit()
    db.refresh(row)
    return row


EXPORT_COLUMNS = (
    "id", "upload_id", "rule_id", "rule_name", "severity", "timestamp_iso",
    "src_ip", "dst_ip", "summary", "ai_status", "ai_summary", "ai_observed_behavior",
    "ai_severity_recommendation", "ai_confidence", "ai_benign_explanations", "ai_next_steps",
)
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value: Any) -> Any:
    """Stop spreadsheet programs from running a cell as a formula."""
    if value is None:
        return ""
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def export_alert(row: AlertRow, fmt: str) -> Tuple[bytes, str, str]:
    """Return (body, media type, file name) for one investigated alert."""
    filename = f"alert-{row.id}-investigation.{fmt}"
    if fmt == "json":
        doc = {
            "id": row.id, "upload_id": row.upload_id, "rule_id": row.rule_id,
            "rule_name": row.rule_name, "severity": row.severity,
            "timestamp_iso": row.timestamp_iso, "src_ip": row.src_ip, "dst_ip": row.dst_ip,
            "summary": row.summary, "evidence": row.evidence or {},
            "investigation": {"status": row.ai_status, "error": row.ai_error, "report": row.ai_report},
        }
        return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8"), "application/json", filename

    report = row.ai_report or {}
    flat = {
        "id": row.id, "upload_id": row.upload_id, "rule_id": row.rule_id,
        "rule_name": row.rule_name, "severity": row.severity,
        "timestamp_iso": row.timestamp_iso, "src_ip": row.src_ip, "dst_ip": row.dst_ip,
        "summary": row.summary, "ai_status": row.ai_status,
        "ai_summary": report.get("summary"),
        "ai_observed_behavior": report.get("observed_behavior"),
        "ai_severity_recommendation": report.get("severity_recommendation"),
        "ai_confidence": report.get("confidence_score"),
        "ai_benign_explanations": "; ".join(report.get("benign_explanations") or []),
        "ai_next_steps": "; ".join(report.get("next_steps") or []),
    }
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS)
    writer.writeheader()
    writer.writerow({k: _csv_cell(flat[k]) for k in EXPORT_COLUMNS})
    # utf-8-sig adds a byte-order mark so Excel reads non-ASCII text correctly
    return buf.getvalue().encode("utf-8-sig"), "text/csv", filename
