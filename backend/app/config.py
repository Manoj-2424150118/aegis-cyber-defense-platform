"""Application configuration.

All secrets come from the environment. Safe defaults exist only so the
project runs locally out-of-the-box for demos and tests; production
deployments MUST override ``AEGIS_SECRET_KEY`` (see ``.env.example``).
"""

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env")

    app_name: str = "Aegis — Personal Cyber Defense Platform"
    environment: str = "development"
    secret_key: str = "dev-only-change-me-in-production-please-32chars"  # noqa: S105
    # Freemium tiers (docs/FREEMIUM.md). Env-overridable: AEGIS_ANON_DAILY_SCAN_LIMIT etc.
    anon_daily_scan_limit: int = 10
    account_daily_scan_limit: int = 50
    vault_free_item_limit: int = 20
    history_free_days: int = 30
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    database_url: str = "sqlite:///./aegis.db"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]
    rate_limit_per_minute: int = 120
    auth_rate_limit_per_minute: int = 10
    # Endpoints that make the server fetch/DNS-resolve third-party targets
    # are far more expensive (and abusable as an anonymous proxy) than a
    # local analysis, so they get a much tighter per-IP budget.
    fetch_rate_limit_per_minute: int = 12
    trending_cache_seconds: int = 60  # public trends are aggregates; serve them stale-tolerant
    trust_proxy: bool = False  # set True only behind a proxy that sets X-Forwarded-For
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB
    hibp_api_url: str = "https://api.pwnedpasswords.com/range/"

    @field_validator("database_url", mode="before")
    @classmethod
    def _normalise_database_url(cls, v: object) -> object:
        # Hosted Postgres providers (Neon, Supabase, …) hand out
        # "postgresql://" URLs, which SQLAlchemy maps to the legacy
        # psycopg2 dialect. Pin the installed psycopg (v3) driver
        # explicitly so a pasted provider URL works as-is.
        if isinstance(v, str):
            for prefix in ("postgresql://", "postgres://"):
                if v.startswith(prefix):
                    return "postgresql+psycopg://" + v[len(prefix):]
        return v


settings = Settings()
