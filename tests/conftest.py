"""Pytest fixtures: a fresh schema + deterministic alert data per test.

Requires a reachable PostgreSQL. Locally:
    docker run -d --name soc-pg -e POSTGRES_PASSWORD=postgres \
        -e POSTGRES_DB=soc_test -p 5433:5432 postgres:16
    export DATABASE_URL=postgresql://postgres:postgres@localhost:5433/soc_test
CI sets DATABASE_URL to a postgres service container.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# These must be set before importing app: app.py reads DATABASE_URL and
# FLASK_SECRET_KEY at module load (and exits if the secret is missing).
# pytest imports conftest before any test module, so this runs first even for
# test files that do `from app import ...` at top level.
os.environ.setdefault(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/soc_test"
)
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key")
os.environ.setdefault("ALERTS_API_KEY", API_KEY := "test-api-key")
# DB_ENCRYPTION_KEY intentionally left unset here so the integration tests
# exercise the plaintext (encryption-disabled) path; crypto round-trips are
# covered separately in test_crypto.py.

import bcrypt  # noqa: E402
import psycopg2  # noqa: E402

SCHEMA = (ROOT / "schema.sql").read_text()

# A known analyst account used to authenticate the test client.
TEST_USERNAME = "tester"
TEST_PASSWORD = "test-password"
_PW_HASH = bcrypt.hashpw(TEST_PASSWORD.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")

# Deterministic fixtures. SLA targets: CRITICAL 900s, HIGH 3600s, LOW 86400s.
#   alert 1: CRITICAL, triaged (TP) in 100s   -> within SLA, assigned alice
#   alert 2: CRITICAL, escalated in 2000s     -> BREACH, assigned bob
#   alert 3: LOW, open, aged 2 days            -> BREACH (overdue)
#   alert 4: HIGH, open, just created          -> within SLA
# => SLA: 2 breaches / 4 considered = 50%
# => escalation: 1 escalated / 2 triaged = 50%
FIXTURES = """
INSERT INTO alerts (id, title, category, severity, source, status, assigned_to, created_at) VALUES
    (1, 'crit fast',     'brute_force', 'CRITICAL', 'Auth Logs',     'true_positive', 'alice', now() - interval '1 hour'),
    (2, 'crit slow',     'malware',     'CRITICAL', 'EDR',           'escalated',     'bob',   now() - interval '1 hour'),
    (3, 'low old open',  'anomaly',     'LOW',      'SIEM/UEBA',     'open',          NULL,    now() - interval '2 days'),
    (4, 'high new open', 'phishing',    'HIGH',     'Email Gateway', 'open',          NULL,    now());
INSERT INTO analyst_actions (alert_id, analyst_name, action, response_time_seconds) VALUES
    (1, 'alice', 'classify_tp', 100),
    (2, 'bob',   'escalate',    2000);
-- advance the SERIAL sequence past the explicit ids so fresh inserts don't collide
SELECT setval(pg_get_serial_sequence('alerts', 'id'), (SELECT max(id) FROM alerts));
"""


def _provision():
    """Apply a clean schema + fixtures + a single test analyst account."""
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
        cur.execute(FIXTURES)
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'analyst')",
            (TEST_USERNAME, _PW_HASH),
        )
    conn.close()


@pytest.fixture()
def anon_client():
    """A test client that is NOT logged in (for auth-boundary tests)."""
    import app as soc_app

    _provision()
    # CSRF is disabled in tests so the form/JSON POST fixtures don't each need a
    # token; the protection itself is exercised in test_security.py.
    soc_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return soc_app.app.test_client()


@pytest.fixture()
def provisioned_db():
    """A clean schema + fixtures + test user, without a Flask client.

    For the manage.py / seed.py CLI tests, which talk to the database directly.
    """
    _provision()


@pytest.fixture()
def csrf_client():
    """A NOT-logged-in client with CSRF protection ENABLED, for security tests.

    CSRFProtect runs in a before_request hook, so a tokenless POST is rejected
    before the view (and before login_required) ever runs — no session needed
    to prove the protection is active.
    """
    import app as soc_app

    _provision()
    soc_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    return soc_app.app.test_client()


@pytest.fixture()
def client():
    """An authenticated test client (existing tests run as a logged-in analyst)."""
    import app as soc_app

    _provision()
    # CSRF is disabled in tests so the form/JSON POST fixtures don't each need a
    # token; the protection itself is exercised in test_security.py.
    soc_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    c = soc_app.app.test_client()
    resp = c.post(
        "/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD},
    )
    assert resp.status_code in (200, 302), "test login failed"
    return c
