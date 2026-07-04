"""Tests for the demo-data seeder (seed.py)."""
import os

import psycopg2

import seed


def test_build_alerts_honors_shape():
    alerts = seed.build_alerts()
    assert len(alerts) == 50  # 50 categories paired with 50 severities
    for a in alerts:
        assert a["source"] == seed.SOURCES[a["category"]]
        assert a["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert a["title"] and a["description"] and a["source_ip"]


def test_rand_public_ip_avoids_reserved_ranges():
    for _ in range(200):
        first = int(seed.rand_public_ip().split(".")[0])
        assert 1 <= first <= 223
        assert first not in (10, 127, 169, 172, 192)


def test_rand_internal_ip_is_in_10_block():
    assert seed.rand_internal_ip().startswith("10.")


def test_main_seeds_and_is_idempotent(provisioned_db, capsys):
    seed.main()
    assert "Seeded 50 alerts" in capsys.readouterr().out

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM alerts")
        assert cur.fetchone()[0] == 50                       # replaced the fixtures
        cur.execute("SELECT count(*) FROM alerts WHERE status = 'open'")
        assert cur.fetchone()[0] == 20                       # 50 - 30 closed
        cur.execute("SELECT count(*) FROM analyst_actions")
        assert cur.fetchone()[0] == 30                       # one per closed alert
    conn.close()

    # Running again TRUNCATEs and re-seeds rather than piling on.
    seed.main()
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM alerts")
        assert cur.fetchone()[0] == 50
    conn.close()
