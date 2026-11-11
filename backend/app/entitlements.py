"""Server-side plan entitlements (spec §2/§4, docs/FREEMIUM.md).

The stored ``users.plan`` is what billing last set; the *effective* plan
also honours ``plan_period_end`` — a cancelled Pro subscription stays
Pro until the paid period ends (grace), then falls back to free without
anyone having to run a downgrade job. Every gate (quota, vault cap,
history window, export, API keys, monitoring) must ask here, never
read ``user.plan`` directly and never trust a client-supplied flag.
"""

from datetime import UTC, datetime

from app.models import User


def effective_plan(user: User | None, now: datetime | None = None) -> str:
    if user is None:
        return "anonymous"
    plan = (user.plan or "free").lower()
    if plan != "pro":
        return "free"
    end = user.plan_period_end
    if end is not None:
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        if (now or datetime.now(UTC)) >= end:
            return "free"
    return "pro"


def is_pro(user: User | None) -> bool:
    return effective_plan(user) == "pro"
