"""ORM models. The vault stores ciphertext only — never plaintext secrets."""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _now() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    plan: Mapped[str] = mapped_column(String(16), default="free")
    # Billing linkage (spec §4). Ids only — card data never touches this
    # service; checkout and payment happen on the provider's hosted page.
    billing_customer_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    billing_subscription_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    plan_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scan_type: Mapped[str] = mapped_column(String(40))
    target: Mapped[str] = mapped_column(String(500))
    risk_score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ScanEvent(Base):
    """Privacy-safe aggregate telemetry behind the public Trends view.

    Deliberately stores NO full URLs, NO email/message content, NO user
    ids and NO IP addresses — only the scan type, verdict, and (for
    flagged links only) the registrable domain and impersonated brand,
    plus finding codes. Enough to show which scams are trending;
    nothing that could identify a person who checked something.
    """

    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(40), index=True)
    verdict: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[int] = mapped_column(Integer)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    brand: Mapped[str | None] = mapped_column(String(80), nullable=True)
    finding_codes: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class VaultItem(Base):
    __tablename__ = "vault_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    # AES-256-GCM output, base64: nonce || ciphertext || tag. Plaintext never stored.
    ciphertext: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ApiKey(Base):
    """Pro API keys. Only an HMAC of the key is stored (see
    app/apikeys.py); the plaintext exists once, in the creation
    response. ``key_prefix`` is the non-secret display fragment."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(80), default="API key")
    key_prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class MonitoredDomain(Base):
    """A domain the owner of an account watches (spec §2). Stores the
    last graded result of the public domain checker so a re-check can
    flag change; no credentials, no private data."""

    __tablename__ = "monitored_domains"
    __table_args__ = (UniqueConstraint("user_id", "domain", name="uq_monitor_user_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_grade: Mapped[str | None] = mapped_column(String(4), nullable=True)
    last_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    change_detected: Mapped[bool] = mapped_column(Boolean, default=False)


class BillingEvent(Base):
    """One row per accepted webhook delivery — the idempotency ledger.

    Stores a digest of the payload, never the payload itself: webhook
    bodies carry customer email addresses this service has no reason
    to keep a second copy of.
    """

    __tablename__ = "billing_events"
    __table_args__ = (UniqueConstraint("provider", "event_id", name="uq_billing_event"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(20))
    event_id: Mapped[str] = mapped_column(String(160))
    event_type: Mapped[str] = mapped_column(String(80), default="")
    payload_sha256: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(40), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ScanQuota(Base):
    """Daily scan counters for the freemium tiers. The key is an HMAC of
    the caller identity (user id, or edge IP + day salt) — raw IPs are
    never stored (docs/FREEMIUM.md). Rows older than 48h are pruned by
    the quota check itself."""

    __tablename__ = "scan_quota"
    __table_args__ = (UniqueConstraint("key_hash", "day", name="uq_quota_key_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), index=True)
    day: Mapped[str] = mapped_column(String(10))
    count: Mapped[int] = mapped_column(Integer, default=0)
