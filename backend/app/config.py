"""Application configuration.

All secrets come from the environment. Safe defaults exist only so the
project runs locally out-of-the-box for demos and tests; production
deployments MUST override ``AEGIS_SECRET_KEY`` (see ``.env.example``).
"""

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
    trust_proxy: bool = False  # set True only behind a proxy that sets X-Forwarded-For
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB
    hibp_api_url: str = "https://api.pwnedpasswords.com/range/"


settings = Settings()
