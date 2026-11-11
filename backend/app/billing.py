"""Billing provider glue (spec §4) — hosted checkout + signed webhooks.

Design constraints, all deliberate:

* **Disabled by default.** Nothing here runs unless the owner sets
  ``AEGIS_BILLING_ENABLED=true`` after creating the provider account
  and completing KYC. No keys, prices or account ids live in the repo.
* **No SDK dependency.** Checkout is the provider's hosted page
  (Stripe Payment Links / Razorpay Payment Pages) configured by URL;
  webhooks are verified with stdlib HMAC-SHA256, the scheme both
  providers document.
* **Idempotent.** Every webhook is recorded in ``billing_events``
  under a unique (provider, event_id); redeliveries are acknowledged
  without re-applying.
* **Entitlement is the only output.** Events mutate ``users.plan`` and
  its billing linkage fields — nothing else. No credential or vault
  data is ever touched by billing code.
"""

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.models import BillingEvent, User

SIGNATURE_TOLERANCE_SECONDS = 300


def _from_unix(ts) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(ts), tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


# ------------------------------------------------------------------ signatures


def verify_signature(provider: str, body: bytes, headers) -> bool:
    """Constant-time verification of the provider's webhook signature."""
    secret = settings.billing_webhook_secret
    if not secret:
        return False
    if provider == "stripe":
        header = headers.get("stripe-signature", "")
        parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
        timestamp, given = parts.get("t", ""), parts.get("v1", "")
        if not timestamp or not given:
            return False
        try:
            if abs(time.time() - int(timestamp)) > SIGNATURE_TOLERANCE_SECONDS:
                return False
        except ValueError:
            return False
        signed = f"{timestamp}.".encode() + body
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, given)
    if provider == "razorpay":
        given = headers.get("x-razorpay-signature", "")
        if not given:
            return False
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, given)
    return False


def event_id_for(provider: str, event: dict, headers, body: bytes) -> str:
    if provider == "stripe":
        return str(event.get("id") or hashlib.sha256(body).hexdigest())
    return str(headers.get("x-razorpay-event-id") or hashlib.sha256(body).hexdigest())


# ------------------------------------------------------------------ application


def _find_user(db: Session, *, customer_id=None, subscription_id=None, user_id=None, email=None) -> User | None:
    q = db.query(User)
    if user_id:
        found = q.filter(User.id == user_id).first()
        if found:
            return found
    if subscription_id:
        found = q.filter(User.billing_subscription_id == str(subscription_id)).first()
        if found:
            return found
    if customer_id:
        found = q.filter(User.billing_customer_id == str(customer_id)).first()
        if found:
            return found
    if email:
        return q.filter(User.email == str(email)).first()
    return None


def _set_pro(user: User, *, customer_id=None, subscription_id=None, period_end=None) -> None:
    user.plan = "pro"
    if customer_id:
        user.billing_customer_id = str(customer_id)
    if subscription_id:
        user.billing_subscription_id = str(subscription_id)
    if period_end is not None:
        user.plan_period_end = period_end


def _set_free(user: User) -> None:
    user.plan = "free"
    user.plan_period_end = None
    user.billing_subscription_id = None


def _apply_stripe(db: Session, event: dict) -> str:
    etype = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}
    if etype == "checkout.session.completed":
        user = _find_user(
            db,
            customer_id=obj.get("customer"),
            user_id=int(obj["client_reference_id"]) if str(obj.get("client_reference_id", "")).isdigit() else None,
            email=obj.get("customer_email") or (obj.get("customer_details") or {}).get("email"),
        )
        if user is None:
            return "no-matching-user"
        _set_pro(user, customer_id=obj.get("customer"), subscription_id=obj.get("subscription"))
        return "pro-activated"
    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        user = _find_user(db, customer_id=obj.get("customer"), subscription_id=obj.get("id"))
        if user is None:
            return "no-matching-user"
        if obj.get("status") in ("active", "trialing"):
            _set_pro(user, customer_id=obj.get("customer"), subscription_id=obj.get("id"),
                     period_end=_from_unix(obj.get("current_period_end")))
            return "pro-activated"
        if obj.get("status") in ("canceled", "unpaid", "incomplete_expired"):
            _set_free(user)
            return "downgraded"
        return "recorded"  # past_due etc. — grace: keep the current plan
    if etype == "customer.subscription.deleted":
        user = _find_user(db, customer_id=obj.get("customer"), subscription_id=obj.get("id"))
        if user is None:
            return "no-matching-user"
        _set_free(user)
        return "downgraded"
    return "recorded"  # invoice.payment_failed and everything else: audit only


def _apply_razorpay(db: Session, event: dict) -> str:
    etype = event.get("event", "")
    entity = ((event.get("payload") or {}).get("subscription") or {}).get("entity") or {}
    notes = entity.get("notes") or {}
    user = _find_user(
        db,
        customer_id=entity.get("customer_id"),
        subscription_id=entity.get("id"),
        user_id=int(notes["user_id"]) if str(notes.get("user_id", "")).isdigit() else None,
    )
    if user is None:
        return "no-matching-user"
    if etype in ("subscription.activated", "subscription.charged", "subscription.resumed"):
        _set_pro(user, customer_id=entity.get("customer_id"), subscription_id=entity.get("id"),
                 period_end=_from_unix(entity.get("current_end")))
        return "pro-activated"
    if etype in ("subscription.cancelled", "subscription.halted", "subscription.completed"):
        _set_free(user)
        return "downgraded"
    return "recorded"


def apply_webhook(db: Session, provider: str, body: bytes, headers) -> tuple[int, dict]:
    """Verify, de-duplicate and apply one webhook delivery.

    Returns (http_status, payload). The caller owns the transaction.
    """
    if provider not in ("stripe", "razorpay"):
        return 404, {"detail": "Unknown billing provider."}
    if not settings.billing_enabled:
        return 503, {"detail": "Billing is not enabled."}
    if not verify_signature(provider, body, headers):
        return 400, {"detail": "Invalid webhook signature."}
    try:
        event = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return 400, {"detail": "Malformed webhook payload."}
    event_id = event_id_for(provider, event, headers, body)
    existing = (
        db.query(BillingEvent)
        .filter(BillingEvent.provider == provider, BillingEvent.event_id == event_id)
        .first()
    )
    if existing is not None:
        return 200, {"received": True, "duplicate": True}
    outcome = _apply_stripe(db, event) if provider == "stripe" else _apply_razorpay(db, event)
    db.add(
        BillingEvent(
            provider=provider,
            event_id=event_id,
            event_type=str(event.get("type") or event.get("event") or ""),
            payload_sha256=hashlib.sha256(body).hexdigest(),
            outcome=outcome,
        )
    )
    db.commit()
    return 200, {"received": True, "outcome": outcome}
