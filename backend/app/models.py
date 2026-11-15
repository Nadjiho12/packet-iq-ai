"""ORM models. Only derived results are stored - never the uploaded PCAP itself."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(Integer)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    ai_requested: Mapped[bool] = mapped_column(Boolean, default=False)

    alerts: Mapped[List["AlertRow"]] = relationship(
        back_populates="upload", cascade="all, delete-orphan", order_by="AlertRow.id")


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(16), index=True)
    rule_name: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    timestamp_iso: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    # AI investigation outcome: ok | failed | skipped
    ai_status: Mapped[str] = mapped_column(String(16), default="skipped")
    ai_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_report: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)

    upload: Mapped[Upload] = relationship(back_populates="alerts")
