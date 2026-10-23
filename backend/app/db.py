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
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
