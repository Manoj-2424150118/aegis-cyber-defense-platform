"""Application configuration.

All secrets come from the environment. Safe defaults exist only so the
project runs locally out-of-the-box for demos and tests; production
deployments MUST override ``AEGIS_SECRET_KEY`` (see ``.env.example``).
"""

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env")

    app_name: str = "Aegis — Personal Cyber Defense Platform"
    environment: str = "development"
    secret_key: str = "dev-only-change-me-in-production-please-32chars"  # noqa: S105
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
    trusted_proxy_hops: int = 1  # trusted hops appended to X-Forwarded-For from the right
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



    @model_validator(mode="after")
    def _validate_proxy_chain(self):
        # F-03: trusting the proxy chain without knowing how many hops append
        # to it makes the rate limiter key on attacker-controlled data
        # (F-02). Refuse to start rather than run with a spoofable bucket.
        if self.trust_proxy and self.trusted_proxy_hops < 1:
            raise ValueError(
                "AEGIS_TRUST_PROXY is on but AEGIS_TRUSTED_PROXY_HOPS < 1: "
                "refusing to start with an unverifiable proxy chain."
            )
        return self

settings = Settings()
