"""Billing (spec §4): flag-disabled by default, signed + idempotent
webhooks, server-side entitlements with period-end grace."""

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta

from app.config import settings

CREDS = {"email": "buyer@example.com", "password": "StrongPass!2026-secure"}
SECRET = "whsec_test_only_not_a_real_key"


def _register(client, creds=CREDS):
    r = client.post("/api/auth/register", json=creds)
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def _get_user(email=CREDS["email"]):
    from app.db import SessionLocal
    from app.models import User

    db = SessionLocal()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


def _enable(monkeypatch, provider="stripe"):
    monkeypatch.setattr(settings, "billing_enabled", True)
    monkeypatch.setattr(settings, "billing_provider", provider)
    monkeypatch.setattr(settings, "billing_webhook_secret", SECRET)


def _stripe_headers(body: bytes, secret: str = SECRET, ts: int | None = None) -> dict:
    ts = ts or int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return {"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"}


def _stripe_event(etype: str, obj: dict, event_id: str) -> bytes:
    return json.dumps({"id": event_id, "type": etype, "data": {"object": obj}}).encode()


# ------------------------------------------------------------------ disabled


def test_billing_is_inert_by_default(client):
    token = _register(client)
    auth = {"Authorization": f"Bearer {token}"}
    plans = client.get("/api/billing/plans")
    assert plans.status_code == 200
    assert plans.json()["billing_enabled"] is False
    assert plans.json()["tiers"][2]["price_display"] is None  # not on sale, no invented price
    r = client.post("/api/billing/checkout", json={"cycle": "monthly"}, headers=auth)
    assert r.status_code == 503
    body = _stripe_event("checkout.session.completed", {}, "evt_disabled")
    r = client.post("/api/billing/webhook/stripe", content=body, headers=_stripe_headers(body))
    assert r.status_code == 503  # disabled: even a well-signed event is refused


def test_checkout_returns_configured_hosted_url(client, monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(settings, "billing_checkout_url_monthly", "https://checkout.example.invalid/monthly")
    token = _register(client)
    r = client.post("/api/billing/checkout", json={"cycle": "monthly"},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["checkout_url"] == "https://checkout.example.invalid/monthly"
    r = client.post("/api/billing/checkout", json={"cycle": "annual"},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 503  # annual link not configured — no fallback invention


# ------------------------------------------------------------------ webhooks


def test_stripe_checkout_completed_activates_pro_and_is_idempotent(client, monkeypatch):
    _enable(monkeypatch)
    _register(client)
    user = _get_user()
    body = _stripe_event(
        "checkout.session.completed",
        {"customer": "cus_test123", "subscription": "sub_test123",
         "client_reference_id": str(user.id)},
        "evt_activate_1",
    )
    r = client.post("/api/billing/webhook/stripe", content=body, headers=_stripe_headers(body))
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "pro-activated"
    user = _get_user()
    assert user.plan == "pro"
    assert user.billing_customer_id == "cus_test123"
    assert user.billing_subscription_id == "sub_test123"
    # Redelivery (providers retry) must not re-apply or error.
    r = client.post("/api/billing/webhook/stripe", content=body, headers=_stripe_headers(body))
    assert r.status_code == 200
    assert r.json().get("duplicate") is True


def test_stripe_bad_signature_and_stale_timestamp_rejected(client, monkeypatch):
    _enable(monkeypatch)
    body = _stripe_event("checkout.session.completed", {"customer": "cus_x"}, "evt_bad")
    r = client.post("/api/billing/webhook/stripe", content=body,
                    headers=_stripe_headers(body, secret="whsec_wrong"))
    assert r.status_code == 400
    stale = int(time.time()) - 3600
    r = client.post("/api/billing/webhook/stripe", content=body,
                    headers=_stripe_headers(body, ts=stale))
    assert r.status_code == 400


def test_stripe_subscription_deleted_downgrades(client, monkeypatch):
    _enable(monkeypatch)
    _register(client)
    from app.db import SessionLocal
    from app.models import User

    db = SessionLocal()
    u = db.query(User).filter(User.email == CREDS["email"]).first()
    u.plan, u.billing_customer_id, u.billing_subscription_id = "pro", "cus_9", "sub_9"
    db.commit()
    db.close()
    body = _stripe_event("customer.subscription.deleted",
                         {"id": "sub_9", "customer": "cus_9"}, "evt_del_1")
    r = client.post("/api/billing/webhook/stripe", content=body, headers=_stripe_headers(body))
    assert r.json()["outcome"] == "downgraded"
    user = _get_user()
    assert user.plan == "free"
    assert user.billing_subscription_id is None


def test_razorpay_signature_and_activation(client, monkeypatch):
    _enable(monkeypatch, provider="razorpay")
    _register(client)
    user = _get_user()
    event = {
        "event": "subscription.activated",
        "payload": {"subscription": {"entity": {
            "id": "sub_rzp1", "customer_id": "cust_rzp1",
            "current_end": int(time.time()) + 30 * 86400,
            "notes": {"user_id": str(user.id)},
        }}},
    }
    body = json.dumps(event).encode()
    sig = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    r = client.post("/api/billing/webhook/razorpay", content=body,
                    headers={"x-razorpay-signature": sig, "x-razorpay-event-id": "evt_rzp_1"})
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "pro-activated"
    user = _get_user()
    assert user.plan == "pro"
    assert user.plan_period_end is not None
    bad = client.post("/api/billing/webhook/razorpay", content=body,
                      headers={"x-razorpay-signature": "deadbeef"})
    assert bad.status_code == 400


def test_unknown_provider_404(client, monkeypatch):
    _enable(monkeypatch)
    r = client.post("/api/billing/webhook/paypal", content=b"{}")
    assert r.status_code == 404


# ------------------------------------------------------------------ entitlements


def test_expired_pro_falls_back_to_free_everywhere(client, monkeypatch):
    """A Pro plan past its paid period must behave as free: quota caps
    again and /api/billing/me reports the effective plan honestly."""
    token = _register(client)
    from app.db import SessionLocal
    from app.models import User

    db = SessionLocal()
    u = db.query(User).filter(User.email == CREDS["email"]).first()
    u.plan = "pro"
    u.plan_period_end = datetime.now(UTC) - timedelta(days=1)
    db.commit()
    db.close()
    me = client.get("/api/billing/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["plan"] == "pro"  # stored state, as billing left it
    assert me.json()["effective_plan"] == "free"  # what gates actually enforce
    monkeypatch.setattr(settings, "account_daily_scan_limit", 1)
    auth = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/tools/url", json={"url": "https://example.com"}, headers=auth).status_code == 200
    assert client.post("/api/tools/url", json={"url": "https://example.com"}, headers=auth).status_code == 429


def test_billing_events_store_digest_not_payload(client, monkeypatch):
    _enable(monkeypatch)
    _register(client)
    body = _stripe_event("invoice.payment_failed", {"customer": "cus_audit"}, "evt_digest")
    client.post("/api/billing/webhook/stripe", content=body, headers=_stripe_headers(body))
    from app.db import SessionLocal
    from app.models import BillingEvent

    db = SessionLocal()
    row = db.query(BillingEvent).first()
    db.close()
    assert row is not None
    assert row.payload_sha256 == hashlib.sha256(body).hexdigest()
    assert not hasattr(row, "payload")  # raw webhook bodies are never persisted
