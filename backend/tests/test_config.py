"""Database-URL normalisation: provider URLs must land on psycopg v3."""

from app.config import Settings


def test_postgresql_url_gets_psycopg_driver():
    s = Settings(database_url="postgresql://u:p@host.example/db?sslmode=require")
    assert s.database_url == "postgresql+psycopg://u:p@host.example/db?sslmode=require"


def test_postgres_short_scheme_also_normalised():
    s = Settings(database_url="postgres://u:p@host.example/db")
    assert s.database_url.startswith("postgresql+psycopg://")


def test_sqlite_url_untouched():
    s = Settings(database_url="sqlite:///./aegis.db")
    assert s.database_url == "sqlite:///./aegis.db"


def test_already_qualified_url_untouched():
    s = Settings(database_url="postgresql+psycopg://u:p@host.example/db")
    assert s.database_url == "postgresql+psycopg://u:p@host.example/db"
