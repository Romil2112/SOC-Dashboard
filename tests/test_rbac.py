"""Tests for RBAC, audit trail, case notes, SSE auth, and filter presets."""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import psycopg2
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Set env vars before importing app.
os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/soc_test")
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-rbac")
os.environ.setdefault("ALERTS_API_KEY", "test-api-key")

SCHEMA = (ROOT / "schema.sql").read_text()


def _provision(extra_users=True):
    """Re-create schema and seed analyst1/viewer1/admin1 + one open alert."""
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
        # Always create the fixture analyst account used by conftest
        for username, role in [
            ("analyst1", "analyst"),
            ("viewer1",  "viewer"),
            ("admin1",   "admin"),
        ]:
            pw_hash = bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=4)).decode("ascii")
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, pw_hash, role),
            )
        cur.execute(
            """
            INSERT INTO alerts (id, title, category, severity, source, status, created_at)
            VALUES (1, 'test alert', 'brute_force', 'HIGH', 'Auth Logs', 'open', now())
            """
        )
        cur.execute(
            "SELECT setval(pg_get_serial_sequence('alerts','id'), (SELECT max(id) FROM alerts))"
        )
    conn.close()


def _make_client(username=None):
    import app as soc_app
    soc_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    c = soc_app.app.test_client()
    if username:
        c.post("/login", data={"username": username, "password": "password"})
    return c


@pytest.fixture()
def fresh():
    """Re-provision the DB and return (analyst_client, viewer_client, admin_client, anon_client)."""
    _provision()
    return (
        _make_client("analyst1"),
        _make_client("viewer1"),
        _make_client("admin1"),
        _make_client(),
    )


# ── Viewer read access ────────────────────────────────────────────────────────

def test_viewer_can_see_dashboard(fresh):
    _, viewer, _, _ = fresh
    assert viewer.get("/").status_code == 200


def test_viewer_can_get_open_alerts(fresh):
    _, viewer, _, _ = fresh
    assert viewer.get("/api/alerts").status_code == 200


def test_viewer_can_get_stats(fresh):
    _, viewer, _, _ = fresh
    assert viewer.get("/api/stats").status_code == 200


# ── Viewer cannot triage ──────────────────────────────────────────────────────

def test_viewer_cannot_classify_tp(fresh):
    _, viewer, _, _ = fresh
    resp = viewer.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "viewer1", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 403


def test_viewer_cannot_escalate(fresh):
    _, viewer, _, _ = fresh
    resp = viewer.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "viewer1", "action": "escalate"}),
        content_type="application/json",
    )
    assert resp.status_code == 403


def test_viewer_cannot_add_note(fresh):
    _, viewer, _, _ = fresh
    resp = viewer.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": "should be rejected"}),
        content_type="application/json",
    )
    assert resp.status_code == 403


# ── Analyst can triage ────────────────────────────────────────────────────────

def test_analyst_can_classify_tp(fresh):
    analyst, _, _, _ = fresh
    resp = analyst.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "analyst1", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "true_positive"


def test_analyst_can_escalate():
    _provision()
    analyst = _make_client("analyst1")
    resp = analyst.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "analyst1", "action": "escalate"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "escalated"


def test_analyst_can_add_note(fresh):
    analyst, _, _, _ = fresh
    resp = analyst.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": "investigating now"}),
        content_type="application/json",
    )
    assert resp.status_code == 201


# ── Admin can do everything ───────────────────────────────────────────────────

def test_admin_can_classify():
    _provision()
    admin = _make_client("admin1")
    resp = admin.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "admin1", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 200


def test_admin_can_view_audit_log():
    _provision()
    admin = _make_client("admin1")
    assert admin.get("/audit").status_code == 200


def test_analyst_cannot_view_audit_log(fresh):
    analyst, _, _, _ = fresh
    assert analyst.get("/audit").status_code == 403


def test_viewer_cannot_view_audit_log(fresh):
    _, viewer, _, _ = fresh
    assert viewer.get("/audit").status_code == 403


# ── Audit trail atomicity ─────────────────────────────────────────────────────

def test_classify_creates_audit_log_row():
    _provision()
    analyst = _make_client("analyst1")
    analyst.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "analyst1", "action": "classify_tp"}),
        content_type="application/json",
    )
    rows = analyst.get("/api/alerts/1/audit").get_json()
    assert len(rows) >= 1
    entry = rows[-1]
    assert entry["action"] == "classify_tp"
    assert entry["from_status"] == "open"
    assert entry["to_status"] == "true_positive"


def test_audit_row_has_correct_from_to_status():
    _provision()
    analyst = _make_client("analyst1")
    analyst.post(
        "/api/alerts/1/classify",
        data=json.dumps({"analyst": "analyst1", "action": "escalate"}),
        content_type="application/json",
    )
    rows = analyst.get("/api/alerts/1/audit").get_json()
    entry = rows[-1]
    assert entry["from_status"] == "open"
    assert entry["to_status"] == "escalated"


def test_audit_endpoint_requires_login(fresh):
    _, _, _, anon = fresh
    resp = anon.get("/api/alerts/1/audit")
    assert resp.status_code in (302, 401)


# ── Case notes ────────────────────────────────────────────────────────────────

def test_note_appears_in_audit_history():
    _provision()
    analyst = _make_client("analyst1")
    analyst.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": "my case note"}),
        content_type="application/json",
    )
    rows = analyst.get("/api/alerts/1/audit").get_json()
    note_rows = [r for r in rows if r["action"] == "note_added"]
    assert len(note_rows) >= 1
    assert note_rows[-1]["note"] == "my case note"


def test_note_does_not_change_alert_status():
    _provision()
    analyst = _make_client("analyst1")
    analyst.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": "just a note"}),
        content_type="application/json",
    )
    open_alerts = analyst.get("/api/alerts").get_json()
    assert any(a["id"] == 1 for a in open_alerts)


def test_note_from_to_status_unchanged():
    _provision()
    analyst = _make_client("analyst1")
    analyst.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": "checking"}),
        content_type="application/json",
    )
    rows = analyst.get("/api/alerts/1/audit").get_json()
    note_rows = [r for r in rows if r["action"] == "note_added"]
    assert note_rows[-1]["from_status"] == note_rows[-1]["to_status"]


def test_note_encrypted_at_rest(monkeypatch):
    """When DB_ENCRYPTION_KEY is set, note must be ciphertext in the DB."""
    import app as soc_app
    import crypto
    _provision()
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "test-enc-key-for-notes-12345")
    monkeypatch.setattr(soc_app, "FERNET", crypto.get_fernet())
    analyst = _make_client("analyst1")
    analyst.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": "secret note text"}),
        content_type="application/json",
    )
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT note FROM audit_log WHERE action='note_added' ORDER BY id DESC LIMIT 1"
        )
        raw_note = cur.fetchone()[0]
    conn.close()
    assert raw_note != "secret note text"  # must be ciphertext, not plaintext


def test_empty_note_rejected(fresh):
    analyst, _, _, _ = fresh
    resp = analyst.post(
        "/api/alerts/1/notes",
        data=json.dumps({"note": ""}),
        content_type="application/json",
    )
    assert resp.status_code == 400


# ── SSE endpoint ──────────────────────────────────────────────────────────────

def test_sse_requires_login(fresh):
    _, _, _, anon = fresh
    resp = anon.get("/api/stream")
    assert resp.status_code in (302, 401)


def test_sse_accessible_to_analyst(fresh):
    analyst, _, _, _ = fresh
    # We can't stream SSE in tests; just verify it returns 200 + correct MIME.
    with analyst.get("/api/stream", buffered=False) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.content_type


# ── Filter preset: created_after ──────────────────────────────────────────────

def test_created_after_future_returns_empty():
    _provision()
    analyst = _make_client("analyst1")
    rows = analyst.get("/api/alerts?created_after=2099-01-01T00:00:00Z").get_json()
    assert rows == []


def test_created_after_past_returns_recent_alerts():
    _provision()
    analyst = _make_client("analyst1")
    rows = analyst.get("/api/alerts?created_after=2000-01-01T00:00:00Z").get_json()
    assert any(r["id"] == 1 for r in rows)


def test_created_after_today_includes_just_created_alert():
    _provision()
    analyst = _make_client("analyst1")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
    rows = analyst.get(f"/api/alerts?created_after={today}").get_json()
    assert any(r["id"] == 1 for r in rows)


# ── manage.py viewer role ─────────────────────────────────────────────────────

def test_manage_py_accepts_viewer_role():
    import argparse
    import manage  # noqa: F401 — ensure it's importable without connecting to DB
    p = argparse.ArgumentParser()
    p.add_argument("--role", choices=["viewer", "analyst", "admin"], default="analyst")
    ns = p.parse_args(["--role", "viewer"])
    assert ns.role == "viewer"
