"""Billing endpoints (spec §4). Everything is inert until the owner
enables billing in the environment after completing provider KYC —
see docs/FREEMIUM.md for the activation checklist."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import billing as billing_mod
from app.config import settings
from app.db import get_db
from app.deps import get_current_user
from app.entitlements import effective_plan
from app.models import User

router = APIRouter(prefix="/api/billing", tags=["billing"])


class CheckoutRequest(BaseModel):
    cycle: str = "monthly"  # monthly | annual


@router.get("/plans")
async def plans():
    """Public plan catalogue. Prices are display strings the owner sets
    in the environment when billing goes on sale — empty means the plan
    is not on sale yet, and the UI must say so rather than invent one."""
    return {
        "billing_enabled": settings.billing_enabled,
        "provider": settings.billing_provider or None,
        "tiers": [
            {
                "id": "anonymous",
                "name": "Anonymous",
                "price_display": "Free",
                "scans_per_day": settings.anon_daily_scan_limit,
                "history_days": 0,
                "vault_items": 0,
            },
            {
                "id": "free",
                "name": "Free account",
                "price_display": "Free",
                "scans_per_day": settings.account_daily_scan_limit,
                "history_days": settings.history_free_days,
                "vault_items": settings.vault_free_item_limit,
            },
            {
                "id": "pro",
                "name": "Pro",
                "price_display": settings.pro_price_monthly_display or None,
                "price_annual_display": settings.pro_price_annual_display or None,
                "scans_per_day": None,  # unlimited
                "history_days": None,
                "vault_items": None,
            },
        ],
    }


@router.get("/me")
async def billing_me(user: User = Depends(get_current_user)):
    return {
        "plan": user.plan or "free",
        "effective_plan": effective_plan(user),
        "plan_period_end": user.plan_period_end.isoformat() if user.plan_period_end else None,
        "provider": settings.billing_provider or None,
        "has_subscription": bool(user.billing_subscription_id),
    }


@router.post("/checkout")
async def checkout(body: CheckoutRequest, user: User = Depends(get_current_user)):
    """Return the provider-hosted checkout URL for the chosen cycle.

    PCI-light by construction: card data only ever exists on the
    provider's page. The owner pastes the Payment Link / Payment Page
    URL into the environment; until then this is a clean 503.
    """
    if not settings.billing_enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Billing is not enabled yet — Pro is not on sale.")
    url = settings.billing_checkout_url_annual if body.cycle == "annual" else settings.billing_checkout_url_monthly
    if not url:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Checkout is not configured for this cycle yet.")
    return {"checkout_url": url, "cycle": body.cycle}


@router.post("/webhook/{provider}")
async def webhook(provider: str, request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    code, payload = billing_mod.apply_webhook(db, provider, body, request.headers)
    if code != 200:
        raise HTTPException(code, payload.get("detail", "Webhook rejected."))
    return payload
