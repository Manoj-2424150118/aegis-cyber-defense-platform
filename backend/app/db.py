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


def init_db() -> None:
    from sqlalchemy import inspect, text

    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    # create_all never alters existing tables, so columns added after a
    # database was first created (plan / TOTP in v2.1) are added here.
    # Idempotent; new tables (scan_quota) come from create_all above.
    inspector = inspect(engine)
    if "users" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("users")}
        additions = {
            "plan": "VARCHAR(16) DEFAULT 'free'",
            "totp_secret": "VARCHAR(64)",
            "totp_enabled": "BOOLEAN DEFAULT FALSE",
        }
        with engine.begin() as conn:
            for name, ddl in additions.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))
