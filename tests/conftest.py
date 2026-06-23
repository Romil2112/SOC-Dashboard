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

# Must be set before importing app (it reads DATABASE_URL at import time).
os.environ.setdefault(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/soc_test"
)

import psycopg2  # noqa: E402

SCHEMA = (ROOT / "schema.sql").read_text()

# Deterministic fixtures. SLA targets: CRITICAL 900s, HIGH 3600s, LOW 86400s.
#   alert 1: CRITICAL, triaged in 100s   -> within SLA
#   alert 2: CRITICAL, triaged in 2000s  -> BREACH
#   alert 3: LOW, open, aged 2 days       -> BREACH (overdue)
#   alert 4: HIGH, open, just created     -> within SLA
# => 2 breaches / 4 considered = 50%
FIXTURES = """
INSERT INTO alerts (id, title, category, severity, status, created_at) VALUES
    (1, 'crit fast',     'brute_force', 'CRITICAL', 'true_positive', now() - interval '1 hour'),
    (2, 'crit slow',     'malware',     'CRITICAL', 'true_positive', now() - interval '1 hour'),
    (3, 'low old open',  'anomaly',     'LOW',      'open',          now() - interval '2 days'),
    (4, 'high new open', 'phishing',    'HIGH',     'open',          now());
INSERT INTO analyst_actions (alert_id, analyst_name, action, response_time_seconds) VALUES
    (1, 'alice', 'classify_tp', 100),
    (2, 'bob',   'classify_tp', 2000);
-- advance the SERIAL sequence past the explicit ids so fresh inserts don't collide
SELECT setval(pg_get_serial_sequence('alerts', 'id'), (SELECT max(id) FROM alerts));
"""


@pytest.fixture()
def client():
    import app as soc_app

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
        cur.execute(FIXTURES)
    conn.close()

    soc_app.app.config.update(TESTING=True)
    return soc_app.app.test_client()
