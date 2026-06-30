"""Integration tests for the SOC dashboard API (Flask test client + Postgres)."""
import json
from datetime import datetime, timedelta, timezone

from app import compute_sla

# Matches ALERTS_API_KEY set in conftest.py; required to ingest alerts.
API_HEADERS = {"X-API-Key": "test-api-key"}


def test_pages_render(client):
    assert client.get("/").status_code == 200
    assert client.get("/analyst").status_code == 200


def test_open_alerts_only_and_severity_sorted(client):
    rows = client.get("/api/alerts").get_json()
    assert [r["id"] for r in rows] == [4, 3]          # HIGH before LOW; only open
    assert all(r["status"] == "open" for r in rows)


def test_all_alerts_returns_everything(client):
    rows = client.get("/api/alerts/all").get_json()
    assert len(rows) == 4


def test_stats_counts(client):
    s = client.get("/api/stats").get_json()
    assert s["total"] == 4
    assert s["open"] == 2
    assert s["closed"] == 2
    assert s["by_severity"]["CRITICAL"] == 2


def test_stats_sla_breach_metrics(client):
    sla = client.get("/api/stats").get_json()["sla"]
    assert sla["considered"] == 4
    assert sla["breaches"] == 2          # crit-slow + low-overdue
    assert sla["breach_rate"] == 50.0
    assert sla["by_severity"].get("CRITICAL") == 1
    assert sla["by_severity"].get("LOW") == 1


def test_stats_escalation_metrics(client):
    esc = client.get("/api/stats").get_json()["escalation"]
    assert esc["triaged"] == 2           # alerts 1 (TP) and 2 (escalated)
    assert esc["escalated"] == 1         # alert 2
    assert esc["rate"] == 50.0


def test_stats_by_source_and_assignees(client):
    s = client.get("/api/stats").get_json()
    assert s["by_source"]["EDR"] == 1
    assert s["by_source"]["Auth Logs"] == 1
    assert s["assignees"] == ["alice", "bob"]


def test_filter_alerts_by_severity(client):
    rows = client.get("/api/alerts/all?severity=CRITICAL").get_json()
    assert sorted(r["id"] for r in rows) == [1, 2]


def test_filter_alerts_by_source(client):
    rows = client.get("/api/alerts/all?source=EDR").get_json()
    assert [r["id"] for r in rows] == [2]


def test_filter_alerts_by_assignee(client):
    rows = client.get("/api/alerts/all?assigned_to=bob").get_json()
    assert [r["id"] for r in rows] == [2]


def test_filter_combines_with_open_queue(client):
    # The open queue honors filters too: only open + HIGH -> alert 4.
    rows = client.get("/api/alerts?severity=HIGH").get_json()
    assert [r["id"] for r in rows] == [4]


def test_classify_updates_status_and_closes_alert(client):
    resp = client.post(
        "/api/alerts/4/classify",
        data=json.dumps({"analyst": "carol", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "true_positive"
    # alert 4 should no longer appear in the open queue
    open_ids = [r["id"] for r in client.get("/api/alerts").get_json()]
    assert 4 not in open_ids


def test_classify_requires_analyst(client):
    resp = client.post(
        "/api/alerts/4/classify",
        data=json.dumps({"action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_classify_rejects_unknown_action(client):
    resp = client.post(
        "/api/alerts/4/classify",
        data=json.dumps({"analyst": "carol", "action": "nope"}),
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_classify_already_closed_returns_409(client):
    # alert 1 is already true_positive in the fixtures; reclassifying is rejected.
    resp = client.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "carol", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 409


def test_compute_sla_counts_medium_severity_breach():
    # MEDIUM target is 4h; a still-open alert aged 5h breaches SLA.
    old = datetime.now(timezone.utc) - timedelta(hours=5)
    sla = compute_sla([{"severity": "MEDIUM", "resp": None, "created_at": old}])
    assert sla["considered"] == 1
    assert sla["breaches"] == 1
    assert sla["by_severity"]["MEDIUM"] == 1


def test_compute_sla_skips_unknown_severity():
    # An unrecognized severity is silently excluded from SLA accounting.
    now = datetime.now(timezone.utc)
    sla = compute_sla([{"severity": "BOGUS", "resp": 10, "created_at": now}])
    assert sla["considered"] == 0
    assert sla["breaches"] == 0
    assert sla["breach_rate"] == 0.0


def test_classify_unknown_alert_404(client):
    resp = client.post(
        "/api/alerts/9999/classify",
        data=json.dumps({"analyst": "carol", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 404


def test_ingest_alert_creates_open_alert(client):
    payload = {
        "title": "Brute-force attack from 10.1.2.3",
        "category": "brute_force",
        "severity": "HIGH",
        "source": "Auth Logs",
        "source_ip": "10.1.2.3",
        "description": "120 failed logins; MITRE T1110.001.",
    }
    resp = client.post("/api/alerts", data=json.dumps(payload),
                       content_type="application/json", headers=API_HEADERS)
    assert resp.status_code == 201
    created = resp.get_json()
    assert created["status"] == "open"
    assert created["source"] == "Auth Logs"
    assert created["source_ip"] == "10.1.2.3"
    # the ingested alert is now in the open queue
    open_titles = [r["title"] for r in client.get("/api/alerts").get_json()]
    assert payload["title"] in open_titles


def test_ingest_requires_title_and_category(client):
    resp = client.post(
        "/api/alerts",
        data=json.dumps({"severity": "HIGH"}),
        content_type="application/json",
        headers=API_HEADERS,
    )
    assert resp.status_code == 400


def test_ingest_rejects_invalid_severity(client):
    resp = client.post(
        "/api/alerts",
        data=json.dumps({"title": "x", "category": "malware", "severity": "BOGUS"}),
        content_type="application/json",
        headers=API_HEADERS,
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Authentication & API-key boundary (new)
# --------------------------------------------------------------------------- #
def test_login_page_renders_when_unauthenticated(anon_client):
    resp = anon_client.get("/login")
    assert resp.status_code == 200
    assert b"Sign in" in resp.data


def test_login_with_valid_credentials_succeeds(anon_client):
    resp = anon_client.post(
        "/login", data={"username": "tester", "password": "test-password"}
    )
    # Redirects to the dashboard on success.
    assert resp.status_code == 302
    assert "/login" not in resp.headers["Location"]


def test_login_with_invalid_credentials_fails_cleanly(anon_client):
    resp = anon_client.post(
        "/login", data={"username": "tester", "password": "wrong"}
    )
    assert resp.status_code == 401
    assert b"Invalid username or password" in resp.data


def test_protected_route_redirects_to_login_when_anonymous(anon_client):
    resp = anon_client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_ingest_without_api_key_returns_401(anon_client):
    resp = anon_client.post(
        "/api/alerts",
        data=json.dumps({"title": "x", "category": "malware", "severity": "HIGH"}),
        content_type="application/json",
    )
    assert resp.status_code == 401


def test_ingest_with_valid_api_key_succeeds(anon_client):
    # Machine-to-machine ingest needs no analyst session, only the API key.
    resp = anon_client.post(
        "/api/alerts",
        data=json.dumps({"title": "x", "category": "malware", "severity": "HIGH"}),
        content_type="application/json",
        headers=API_HEADERS,
    )
    assert resp.status_code == 201


def test_retention_purges_only_old_alerts(client):
    import app as soc_app

    # Fixture alert 3 is 2 days old; the rest are <= 1 hour old.
    deleted = soc_app.purge_old_alerts(1)
    assert deleted == 1
    remaining = [r["id"] for r in client.get("/api/alerts/all").get_json()]
    assert 3 not in remaining
    assert sorted(remaining) == [1, 2, 4]


def test_retention_disabled_is_noop(client):
    import app as soc_app

    assert soc_app.purge_old_alerts(0) == 0
    assert len(client.get("/api/alerts/all").get_json()) == 4


def test_sensitive_fields_encrypted_at_rest(client, monkeypatch):
    """With a key set, sensitive columns are ciphertext in the DB but the API
    still returns plaintext; non-sensitive columns stay clear."""
    import os

    import psycopg2

    import app as soc_app
    import crypto

    monkeypatch.setenv("DB_ENCRYPTION_KEY", "integration-key")
    monkeypatch.setattr(soc_app, "FERNET", crypto.get_fernet())

    payload = {
        "title": "Brute-force from 9.9.9.9",
        "category": "brute_force",
        "severity": "HIGH",
        "source": "Auth Logs",
        "source_ip": "9.9.9.9",
        "description": "secret incident detail",
    }
    resp = client.post("/api/alerts", data=json.dumps(payload),
                       content_type="application/json", headers=API_HEADERS)
    assert resp.status_code == 201
    created = resp.get_json()
    # API response is transparently decrypted.
    assert created["source_ip"] == "9.9.9.9"
    assert created["title"] == payload["title"]
    assert created["description"] == payload["description"]

    # Raw DB row holds ciphertext for sensitive fields, plaintext for the rest.
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT title, source_ip, description, severity, source "
            "FROM alerts WHERE id = %s",
            (created["id"],),
        )
        title, source_ip, description, severity, source = cur.fetchone()
    conn.close()
    assert source_ip != "9.9.9.9"
    assert title != payload["title"]
    assert description != payload["description"]
    assert severity == "HIGH"          # not encrypted (used in queries)
    assert source == "Auth Logs"       # not encrypted
