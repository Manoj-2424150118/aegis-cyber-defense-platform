import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("AEGIS_DATABASE_URL", "sqlite://")
# Freemium quotas are exercised explicitly in test_freemium_v21 with
# monkeypatched limits; the rest of the suite must not be throttled.
os.environ.setdefault("AEGIS_ANON_DAILY_SCAN_LIMIT", "100000")
os.environ.setdefault("AEGIS_ACCOUNT_DAILY_SCAN_LIMIT", "100000")  # in-memory for tests

import pytest
from fastapi.testclient import TestClient

from app.db import Base, engine
from app.main import app
from app.rate_limit import account_limiter, auth_limiter, fetch_limiter, general_limiter
from app.routers import tools as tools_router


@pytest.fixture(autouse=True)
def _fresh_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    general_limiter.reset()
    auth_limiter.reset()
    account_limiter.reset()
    fetch_limiter.reset()
    tools_router._recent_events.clear()
    tools_router._trending_cache = None
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c
