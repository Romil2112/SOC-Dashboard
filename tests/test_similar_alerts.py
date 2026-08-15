"""Tests for 1C: semantic alert similarity (fastembed + pgvector)."""
import logging
import sys
import types
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


def test_similar_returns_list(client, monkeypatch):
    # Model "available" but no embedding rows → empty list, not 503.
    import app as soc_app
    monkeypatch.setattr(soc_app, "_EMBEDDING_MODEL", MagicMock())
    res = client.get("/api/alerts/1/similar")
    assert res.status_code == 200
    assert isinstance(res.get_json(), list)


def test_similar_returns_empty_for_alert_without_embedding(client, monkeypatch):
    import app as soc_app
    monkeypatch.setattr(soc_app, "_EMBEDDING_MODEL", MagicMock())
    res = client.get("/api/alerts/1/similar")
    assert res.get_json() == []


def test_similar_returns_empty_gracefully_for_nonexistent_alert(client, monkeypatch):
    # alert_id 9999 doesn't exist — no embedding row, so returns [].
    import app as soc_app
    monkeypatch.setattr(soc_app, "_EMBEDDING_MODEL", MagicMock())
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


def test_embedding_failure_sets_sentinel_and_logs(monkeypatch, caplog):
    """TextEmbedding raising must log a warning and set the sentinel (not None)."""
    import app as soc_app

    monkeypatch.setattr(soc_app, "_EMBEDDING_MODEL", None)

    fake_fastembed = types.ModuleType("fastembed")
    call_count = []

    def _raising(model_name):
        call_count.append(1)
        raise RuntimeError("model download failed: connection refused")

    fake_fastembed.TextEmbedding = _raising
    monkeypatch.setitem(sys.modules, "fastembed", fake_fastembed)

    with caplog.at_level(logging.WARNING, logger="app"):
        result1 = soc_app._get_embedding_model()
        result2 = soc_app._get_embedding_model()

    assert result1 is None
    assert result2 is None
    assert len(call_count) == 1, "TextEmbedding must not be constructed again after failure"
    assert any(
        "fastembed" in r.message and "failed" in r.message
        for r in caplog.records
    ), "a WARNING about the failure must be emitted"
    assert soc_app._EMBEDDING_MODEL is soc_app._EMBEDDING_LOAD_FAILED


def test_embeddings_available_false_after_failure(monkeypatch):
    """_embeddings_available() must return False when sentinel is set."""
    import app as soc_app
    monkeypatch.setattr(soc_app, "_EMBEDDING_MODEL", soc_app._EMBEDDING_LOAD_FAILED)
    assert soc_app._embeddings_available() is False


def test_similar_returns_503_when_embeddings_unavailable(client, monkeypatch):
    """GET /api/alerts/<id>/similar must return 503 when embedding model failed."""
    import app as soc_app
    monkeypatch.setattr(soc_app, "_EMBEDDING_MODEL", soc_app._EMBEDDING_LOAD_FAILED)
    res = client.get("/api/alerts/1/similar")
    assert res.status_code == 503
    body = res.get_json()
    assert body["error"] == "embeddings_unavailable"


def test_embedding_insert_failure_logs_warning_and_ingest_succeeds(client, monkeypatch, caplog):
    """When the alert_embeddings INSERT raises, a warning must be logged and ingest still returns 201."""
    import app as soc_app

    fake_vec = "[" + ",".join("0.100000" for _ in range(384)) + "]"
    monkeypatch.setattr(soc_app, "_embed_text", lambda text: fake_vec)

    original_get_conn = soc_app.get_conn
    call_count = []

    def get_conn_counting():
        call_count.append(1)
        if len(call_count) >= 2:
            raise RuntimeError("pgvector not available in this environment")
        return original_get_conn()

    monkeypatch.setattr(soc_app, "get_conn", get_conn_counting)

    with caplog.at_level(logging.WARNING, logger="app"):
        res = client.post(
            "/api/alerts",
            json={"title": "Embed insert fail test", "category": "anomaly", "severity": "LOW"},
            headers=API_HEADERS,
        )

    assert res.status_code == 201, f"Ingest must succeed even if embedding INSERT fails: {res.get_json()}"
    assert any(
        "alert_embeddings" in r.message for r in caplog.records
    ), "a WARNING about the embedding insert failure must be logged"


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
