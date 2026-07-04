"""Security-control tests: CSRF protection, ingest exemption, and JSON errors.

These pin the commit-1 hardening in place — a session POST without a CSRF token
is rejected, the machine-to-machine ingest route stays exempt (it authenticates
by X-API-Key, not a cookie), and API errors come back as JSON rather than
Flask's default HTML error pages (which can leak internals).
"""
import json

API_HEADERS = {"X-API-Key": "test-api-key"}


def test_session_post_without_csrf_token_is_rejected(csrf_client):
    resp = csrf_client.post(
        "/api/alerts/4/classify",
        data=json.dumps({"analyst": "carol", "action": "classify_tp"}),
        content_type="application/json",
    )
    assert resp.status_code == 400  # CSRF blocks it before the view runs


def test_ingest_route_is_csrf_exempt(csrf_client):
    # Same CSRF-enabled client, but the X-API-Key ingest path is exempt, so a
    # tokenless request still succeeds.
    resp = csrf_client.post(
        "/api/alerts",
        data=json.dumps({"title": "x", "category": "malware", "severity": "HIGH"}),
        content_type="application/json",
        headers=API_HEADERS,
    )
    assert resp.status_code == 201


def test_unknown_route_returns_json_not_html(client):
    resp = client.get("/api/definitely-not-a-route")
    assert resp.status_code == 404
    assert resp.is_json
    assert resp.get_json()["error"]


def test_client_error_body_is_json(client):
    # A 400 from abort() flows through the JSON error handler and echoes the
    # (safe, analyst-facing) description.
    resp = client.post(
        "/api/alerts/4/classify",
        data=json.dumps({"action": "classify_tp"}),  # missing analyst
        content_type="application/json",
    )
    assert resp.status_code == 400
    assert "analyst" in resp.get_json()["error"]
