"""Runtime configuration, read from environment variables (and .env if present).

No secrets live here. AI_* and SMTP_* variables are read by ai_agent.py / notifier.py.

  DATABASE_URL        SQLAlchemy URL            default: sqlite:///./packetiq.db
  MAX_UPLOAD_MB       max PCAP upload size      default: 25
  CORS_ORIGINS        comma-separated origins   default: http://localhost:5173,http://127.0.0.1:5173
  MAX_AI_ALERTS       optional cap on AI calls   default: no cap (unset, empty or 0)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

try:  # optional: load .env if python-dotenv is installed
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass


def _int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except ValueError:
        return default


def _optional_cap(name: str) -> Optional[int]:
    """A positive number caps the AI calls. Unset, empty, zero or invalid means no cap."""
    try:
        value = int(os.environ.get(name, "").strip() or 0)
    except ValueError:
        return None
    return value if value > 0 else None


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.environ.get("DATABASE_URL", "sqlite:///./packetiq.db"))
    max_upload_mb: int = field(default_factory=lambda: _int("MAX_UPLOAD_MB", 25))
    max_ai_alerts: Optional[int] = field(default_factory=lambda: _optional_cap("MAX_AI_ALERTS"))
    cors_origins: List[str] = field(default_factory=lambda: [
        o.strip() for o in os.environ.get(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()
    ])

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


def get_settings() -> Settings:
    """Fresh settings per call so tests can change the environment."""
    return Settings()
