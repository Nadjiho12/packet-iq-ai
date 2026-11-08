"""SMTP (STARTTLS) alert notifier. Never raises; never logs credentials.

Environment variables:
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD,
  SMTP_FROM (default SMTP_USER), ALERT_EMAIL_TO
Notification is silently skipped (returns False) if config is incomplete.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Dict, Optional

logger = logging.getLogger("packetiq.notifier")


def _load_smtp_config() -> Optional[Dict[str, Any]]:
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    to = os.environ.get("ALERT_EMAIL_TO", "").strip()
    if not (host and user and password and to):
        return None
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError:
        port = 587
    return {"host": host, "port": port, "user": user, "password": password,
            "from": os.environ.get("SMTP_FROM", user), "to": to}


def build_message(result: Dict[str, Any], sender: str, to: str) -> EmailMessage:
    alert = result.get("alert", {})
    report = result.get("report")
    sev = (report or {}).get("severity_recommendation") or alert.get("severity", "unknown")
    msg = EmailMessage()
    msg["Subject"] = f"[PacketIQ][{str(sev).upper()}] {alert.get('rule_id', 'ALERT')} detected"
    msg["From"], msg["To"] = sender, to
    lines = [
        f"Rule: {alert.get('rule_id')} {alert.get('rule_name', '')}".strip(),
        f"Time: {alert.get('timestamp_iso') or alert.get('timestamp')}",
        f"Source: {alert.get('src_ip') or 'n/a'} -> {alert.get('dst_ip') or 'n/a'}",
        f"Detection: {alert.get('summary')}",
        "",
    ]
    if report:
        lines += [
            f"Summary: {report['summary']}",
            f"Observed behavior: {report['observed_behavior']}",
            f"Recommended severity: {report['severity_recommendation']} "
            f"(confidence {report['confidence_score']:.2f})",
            "Benign explanations: " + "; ".join(report["benign_explanations"]),
            "Next steps: " + "; ".join(report["next_steps"]),
        ]
    else:
        lines.append(f"AI investigation unavailable: {result.get('investigation_error')}")
        lines.append("Original detection alert preserved.")
    msg.set_content("\n".join(lines))
    return msg


def send_alert_email(result: Dict[str, Any]) -> bool:
    """Send notification. True on success, False if skipped or failed."""
    cfg = _load_smtp_config()
    if cfg is None:
        logger.info("SMTP not configured; notification skipped")
        return False
    try:
        msg = build_message(result, cfg["from"], cfg["to"])
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(cfg["user"], cfg["password"])
            server.send_message(msg)
        logger.info("Alert email sent")
        return True
    except Exception as exc:  # type only - exception text may echo credentials
        logger.error("Alert email failed: %s", type(exc).__name__)
        return False
