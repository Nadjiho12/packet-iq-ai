"""SQLAlchemy engine/session setup (SQLite by default)."""
from __future__ import annotations

from typing import Iterator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.config import get_settings


class Base(DeclarativeBase):
    pass


def make_engine(url: Optional[str] = None) -> Engine:
    url = url or get_settings().database_url
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url in ("sqlite://", "sqlite:///"):
            kwargs["poolclass"] = StaticPool  # one shared connection for in-memory DBs
    return create_engine(url, **kwargs)


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db(bind: Optional[Engine] = None) -> None:
    from backend.app import models  # noqa: F401  (register tables)
    Base.metadata.create_all(bind or engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
