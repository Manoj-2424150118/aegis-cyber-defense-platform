"""Database setup (SQLAlchemy 2.0). SQLite by default, PostgreSQL via env."""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings

_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}
# In-memory SQLite (tests) needs a single shared connection, otherwise each
# pooled connection sees a different empty database.
_pool_kwargs = (
    {"poolclass": StaticPool}
    if settings.database_url in ("sqlite://", "sqlite:///:memory:")
    else {"pool_pre_ping": True}
)
engine = create_engine(settings.database_url, connect_args=_connect_args, **_pool_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _add_user_columns() -> None:
    """Additive columns for the users table (create_all never alters).

    ALTER TABLE needs an exclusive lock, which a still-serving previous
    instance can transiently block. Each attempt therefore runs with a
    short lock timeout and the caller retries — a blocked migration must
    fail fast and visibly, never hang startup silently (the v2.1.0
    deploy timed out on exactly this shape of wait).
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("users")}
    additions = {
        "plan": "VARCHAR(16) DEFAULT 'free'",
        "totp_secret": "VARCHAR(64)",
        "totp_enabled": "BOOLEAN DEFAULT FALSE",
    }
    missing = {k: v for k, v in additions.items() if k not in existing}
    if not missing:
        return
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SET LOCAL lock_timeout = '4000'"))
        for name, ddl in missing.items():
            conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))


def init_db() -> None:
    import logging
    import time

    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    log = logging.getLogger("aegis.db")
    for attempt in range(1, 7):
        try:
            _add_user_columns()
            return
        except Exception as exc:  # noqa: BLE001 — retried, then raised loudly
            log.warning("schema migration attempt %s/6 failed: %s", attempt, exc)
            time.sleep(5)
    raise RuntimeError("schema migration did not complete after 6 attempts")
