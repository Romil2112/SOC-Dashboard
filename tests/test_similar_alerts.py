"""Tests for 1C: semantic alert similarity (fastembed + pgvector)."""
import pytest
from unittest.mock import MagicMock

API_HEADERS = {"X-API-Key": "test-api-key"}


# ── unit: _embed_text / _get_embedding_model ──────────────────────────────────

def test_embed_text_returns_none_when_model_unavailable(monkeypatch):
    import app as soc_app
    monkeypatch.setattr(soc_app, "_get_embedding_model", lambda: None)
    assert soc_app._embed_text("brute force login") is None


def test_embed_text_returns_pgvector_literal(monkeypatch):
    import app as soc_app
    fake = MagicMock()
    fake.embed.return_value = iter([[0.5] * 384])
    monkeypatch.setattr(soc_app, "_get_embedding_model", lambda: fake)
    out = soc_app._embed_text("lateral movement from 10.0.0.5")
    assert out.startswith("[") and out.endswith("]")
    assert out.count(",") == 383  # 384 elements → 383 commas


def test_embed_text_vector_has_correct_element_count(monkeypatch):
    import app as soc_app
    fake = MagicMock()
    fake.embed.return_value = iter([[0.0] * 384])
    monkeypatch.setattr(soc_app, "_get_embedding_model", lambda: fake)
    out = soc_app._embed_text("port scan detected")
    vals = [float(x) for x in out.strip("[]").split(",")]
    assert len(vals) == 384


# ── integration: GET /api/alerts/<id>/similar ─────────────────────────────────

def test_similar_requires_login(anon_client):
    res = anon_client.get("/api/alerts/1/similar")
    assert res.status_code in (302, 401)


def test_similar_returns_list(client):
    # Alert 1 exists (from conftest fixture) but has no embedding yet → returns [].
    res = client.get("/api/alerts/1/similar")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_similar_returns_empty_for_alert_without_embedding(client):
    res = client.get("/api/alerts/1/similar")
    assert res.get_json() == []


def test_similar_returns_empty_gracefully_for_nonexistent_alert(client):
    # alert_id 9999 doesn't exist — no embedding row, so returns [].
    res = client.get("/api/alerts/9999/similar")
    assert res.status_code == 200
    assert res.get_json() == []


# ── integration: ingest still succeeds without embedding model ────────────────

def test_ingest_succeeds_when_embed_text_returns_none(client, monkeypatch):
    import app as soc_app
    monkeypatch.setattr(soc_app, "_embed_text", lambda text: None)
    res = client.post(
        "/api/alerts",
        json={"title": "No-embed test", "category": "anomaly", "severity": "LOW"},
        headers=API_HEADERS,
    )
    assert res.status_code == 201
    assert res.get_json()["title"] == "No-embed test"


def test_ingest_succeeds_when_embed_text_returns_vector(client, monkeypatch):
    import app as soc_app
    fake_vec = "[" + ",".join("0.100000" for _ in range(384)) + "]"
    monkeypatch.setattr(soc_app, "_embed_text", lambda text: fake_vec)
    res = client.post(
        "/api/alerts",
        json={
            "title": "Lateral movement from 10.0.0.5",
            "category": "malware",
            "severity": "HIGH",
            "description": "Suspicious SMB traffic pattern",
        },
        headers=API_HEADERS,
    )
    # Ingest must succeed even if the alert_embeddings INSERT fails (no pgvector).
    assert res.status_code == 201
    body = res.get_json()
    assert body["category"] == "malware"
    assert body["severity"] == "HIGH"
