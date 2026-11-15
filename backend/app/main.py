"""PacketIQ AI - FastAPI application (Week 4).

Run:  uvicorn backend.app.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.app import service, settings_store
from backend.app.config import get_settings
from backend.app.database import get_db, init_db
from backend.app.models import AlertRow, Upload

log = logging.getLogger("packetiq.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    settings_store.apply_to_env()
    yield


app = FastAPI(title="PacketIQ AI", version="0.4.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=get_settings().cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["*"],
)

SEVERITIES = ("low", "medium", "high", "critical")


# --------------------------------------------------------------------- schemas
def _as_utc(v):
    """SQLite drops tzinfo; every stored timestamp is UTC, so re-attach it."""
    return v.replace(tzinfo=timezone.utc) if isinstance(v, datetime) and v.tzinfo is None else v


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    upload_id: int
    rule_id: str
    rule_name: str
    severity: str
    timestamp_iso: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    summary: str
    evidence: Dict[str, Any]
    ai_status: str
    ai_error: Optional[str]
    ai_report: Optional[Dict[str, Any]]
    notified: bool


class UploadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    filename: str
    size_bytes: int
    uploaded_at: datetime
    packet_count: int
    flow_count: int
    alert_count: int
    ai_requested: bool

    _utc = field_validator("uploaded_at")(_as_utc)


class UploadResult(UploadOut):
    alerts: List[AlertOut]


class Metrics(BaseModel):
    total_packets: int
    active_flows: int
    total_alerts: int
    total_uploads: int
    alerts_by_severity: Dict[str, int]
    last_upload_at: Optional[datetime]

    _utc = field_validator("last_upload_at")(_as_utc)


class AiSettingsIn(BaseModel):
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    model: Optional[str] = None


class AiSettingsOut(BaseModel):
    configured: bool
    source: Optional[str]
    masked_key: Optional[str]
    api_url: Optional[str]
    model: Optional[str]


class AlertPage(BaseModel):
    total: int
    items: List[AlertOut]


# ------------------------------------------------------------------- endpoints
@app.get("/api/v1/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/metrics", response_model=Metrics)
def metrics(db: Session = Depends(get_db)) -> Metrics:
    pk, fl, n_up, last = db.execute(select(
        func.coalesce(func.sum(Upload.packet_count), 0),
        func.coalesce(func.sum(Upload.flow_count), 0),
        func.count(Upload.id), func.max(Upload.uploaded_at))).one()
    by_sev = {s: 0 for s in SEVERITIES}
    for sev, n in db.execute(select(AlertRow.severity, func.count()).group_by(AlertRow.severity)):
        by_sev[sev] = n
    return Metrics(total_packets=int(pk), active_flows=int(fl), total_alerts=sum(by_sev.values()),
                   total_uploads=int(n_up), alerts_by_severity=by_sev, last_upload_at=last)


@app.get("/api/v1/alerts", response_model=AlertPage)
def list_alerts(severity: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=200),
                offset: int = Query(0, ge=0), db: Session = Depends(get_db)) -> AlertPage:
    if severity is not None and severity not in SEVERITIES:
        raise HTTPException(422, f"severity must be one of {', '.join(SEVERITIES)}")
    q = select(AlertRow)
    count_q = select(func.count(AlertRow.id))
    if severity:
        q, count_q = q.where(AlertRow.severity == severity), count_q.where(AlertRow.severity == severity)
    items = db.scalars(q.order_by(desc(AlertRow.id)).limit(limit).offset(offset)).all()
    return AlertPage(total=db.scalar(count_q) or 0, items=[AlertOut.model_validate(a) for a in items])


@app.get("/api/v1/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertRow:
    row = db.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found")
    return row


@app.get("/api/v1/uploads", response_model=List[UploadOut])
def list_uploads(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    return db.scalars(select(Upload).order_by(desc(Upload.id)).limit(limit)).all()


@app.post("/api/v1/upload", response_model=UploadResult, status_code=201)
def upload_pcap(file: UploadFile = File(...), ai: bool = Query(False), notify: bool = Query(False),
                db: Session = Depends(get_db)) -> UploadResult:
    """Validate, process and store results for one PCAP. The file itself is deleted afterwards."""
    settings = get_settings()
    name = service.safe_filename(file.filename or "")
    path: Optional[str] = None
    try:
        service.validate_name(name)
        path, size = service.spool_to_temp(file.file, settings.max_upload_bytes)
        row = service.process_pcap(db, path, name, size, use_ai=ai, notify=notify,
                                   max_ai_alerts=settings.max_ai_alerts)
        return UploadResult.model_validate(row)
    except service.UploadError as exc:
        raise HTTPException(exc.status, exc.message) from None
    finally:
        if path:
            service.remove_quietly(path)  # never keep uploaded captures


@app.delete("/api/v1/data", status_code=204)
def reset_data(db: Session = Depends(get_db)) -> None:
    """Delete all stored uploads and alerts (demo/testing helper)."""
    for row in db.scalars(select(Upload)).all():
        db.delete(row)
    db.commit()


# ----------------------------------------------------------------- AI settings
@app.get("/api/v1/settings/ai", response_model=AiSettingsOut)
def get_ai_settings() -> Dict[str, Any]:
    """Whether an AI key is set. The key itself is never returned, only a masked hint."""
    return settings_store.status()


@app.put("/api/v1/settings/ai", response_model=AiSettingsOut)
def save_ai_settings(body: AiSettingsIn) -> Dict[str, Any]:
    try:
        settings_store.save(body.api_key, body.api_url, body.model)
    except settings_store.SettingsError as exc:
        raise HTTPException(422, str(exc)) from None
    return settings_store.status()


@app.delete("/api/v1/settings/ai", response_model=AiSettingsOut)
def remove_ai_settings() -> Dict[str, Any]:
    settings_store.clear()
    return settings_store.status()


# ------------------------------------------------------- single-alert actions
@app.post("/api/v1/alerts/{alert_id}/investigate", response_model=AlertOut)
def investigate_one(alert_id: int, db: Session = Depends(get_db)) -> AlertRow:
    """Run the AI investigation for one stored alert. The result is saved on that alert."""
    row = db.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found")
    return service.investigate_stored(db, row)


@app.get("/api/v1/alerts/{alert_id}/export")
def export_one(alert_id: int,
               fmt: str = Query("json", alias="format", pattern="^(json|csv)$"),
               db: Session = Depends(get_db)) -> Response:
    """Download one investigated alert as JSON or CSV. Refused until the alert has been investigated."""
    row = db.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found")
    if row.ai_status != "ok":
        raise HTTPException(409, "Investigate this alert before saving it.")
    body, media_type, filename = service.export_alert(row, fmt)
    return Response(content=body, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
