"""Tests for GET /api/navigator-layer.

Uses the same `client` and `anon_client` fixtures from conftest.py.
The FIXTURES data (4 alerts: brute_force/CRITICAL, malware/CRITICAL,
anomaly/LOW, phishing/HIGH) drives all assertions about technique IDs and scores.
"""
import json


def test_navigator_layer_requires_auth(anon_client):
    rv = anon_client.get("/api/navigator-layer")
    assert rv.status_code in (401, 302)


def test_navigator_layer_authenticated_returns_200(client):
    rv = client.get("/api/navigator-layer")
    assert rv.status_code == 200


def test_navigator_layer_content_type_json(client):
    rv = client.get("/api/navigator-layer")
    assert rv.content_type.startswith("application/json")


def test_navigator_layer_domain(client):
    data = client.get("/api/navigator-layer").get_json()
    assert data["domain"] == "enterprise-attack"


def test_navigator_layer_version_fields(client):
    data = client.get("/api/navigator-layer").get_json()
    assert data["versions"]["layer"]     == "4.5"
    assert data["versions"]["navigator"] == "4.9"
    assert data["versions"]["attack"]    == "14"


def test_navigator_layer_has_techniques_list(client):
    data = client.get("/api/navigator-layer").get_json()
    assert isinstance(data["techniques"], list)


def test_navigator_layer_brute_force_maps_to_t1110(client):
    data     = client.get("/api/navigator-layer").get_json()
    ids      = {t["techniqueID"] for t in data["techniques"]}
    assert "T1110.001" in ids


def test_navigator_layer_brute_force_critical_scores_100(client):
    data = client.get("/api/navigator-layer").get_json()
    bf   = next(t for t in data["techniques"] if t["techniqueID"] == "T1110.001")
    assert bf["score"] == 100


def test_navigator_layer_phishing_maps_to_t1566(client):
    data = client.get("/api/navigator-layer").get_json()
    ids  = {t["techniqueID"] for t in data["techniques"]}
    assert "T1566" in ids


def test_navigator_layer_phishing_high_scores_75(client):
    data    = client.get("/api/navigator-layer").get_json()
    phish   = next(t for t in data["techniques"] if t["techniqueID"] == "T1566")
    assert phish["score"] == 75


def test_navigator_layer_anomaly_maps_to_t1078(client):
    data = client.get("/api/navigator-layer").get_json()
    ids  = {t["techniqueID"] for t in data["techniques"]}
    assert "T1078" in ids


def test_navigator_layer_anomaly_low_scores_25(client):
    data   = client.get("/api/navigator-layer").get_json()
    anomly = next(t for t in data["techniques"] if t["techniqueID"] == "T1078")
    assert anomly["score"] == 25


def test_navigator_layer_malware_maps_to_t1059(client):
    data = client.get("/api/navigator-layer").get_json()
    ids  = {t["techniqueID"] for t in data["techniques"]}
    assert "T1059" in ids


def test_navigator_layer_technique_has_required_keys(client):
    data = client.get("/api/navigator-layer").get_json()
    for t in data["techniques"]:
        assert "techniqueID" in t
        assert "score"       in t
        assert "enabled"     in t
        assert "comment"     in t


def test_navigator_layer_has_gradient(client):
    data = client.get("/api/navigator-layer").get_json()
    g    = data["gradient"]
    assert g["minValue"] == 0
    assert g["maxValue"] == 100


def test_navigator_layer_has_legend_items(client):
    data = client.get("/api/navigator-layer").get_json()
    assert len(data["legendItems"]) == 4


def test_navigator_layer_description_mentions_alert_count(client):
    data = client.get("/api/navigator-layer").get_json()
    # 4 alerts in fixtures
    assert "4" in data["description"]


def test_navigator_layer_no_duplicate_technique_ids(client):
    data = client.get("/api/navigator-layer").get_json()
    ids  = [t["techniqueID"] for t in data["techniques"]]
    assert len(ids) == len(set(ids))
