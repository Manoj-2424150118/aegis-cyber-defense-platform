import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("AEGIS_DATABASE_URL", "sqlite://")  # in-memory for tests

import pytest
from fastapi.testclient import TestClient

from app.db import Base, engine
from app.main import app
from app.rate_limit import auth_limiter, general_limiter


@pytest.fixture(autouse=True)
def _fresh_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    general_limiter.reset()
    auth_limiter.reset()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c
