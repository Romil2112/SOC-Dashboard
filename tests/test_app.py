"""Integration tests for the SOC dashboard API (Flask test client + Postgres)."""
import json


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
    resp = client.post("/api/alerts", data=json.dumps(payload), content_type="application/json")
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
    )
    assert resp.status_code == 400


def test_ingest_rejects_invalid_severity(client):
    resp = client.post(
        "/api/alerts",
        data=json.dumps({"title": "x", "category": "malware", "severity": "BOGUS"}),
        content_type="application/json",
    )
    assert resp.status_code == 400
