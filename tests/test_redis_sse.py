"""Unit tests for Redis-backed SSE publish/subscribe paths in app.py."""
import json
import os
import sys
from unittest.mock import MagicMock, patch

# conftest.py sets env vars (FLASK_SECRET_KEY, etc.) before any app import,
# so the ordering here is safe.
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

import app as soc_app  # noqa: E402
from app import _sse_publish  # noqa: E402

# ---------------------------------------------------------------------------
# _sse_publish — Redis path
# ---------------------------------------------------------------------------

def test_sse_publish_calls_redis_when_client_set():
    event = {"type": "alert", "id": 99}
    mock_client = MagicMock()
    with patch.object(soc_app, "_REDIS_CLIENT", mock_client):
        _sse_publish(event)
    mock_client.publish.assert_called_once_with(
        soc_app._REDIS_SSE_CHANNEL, json.dumps(event)
    )


def test_sse_publish_redis_does_not_touch_local_queue():
    mock_client = MagicMock()
    with patch.object(soc_app, "_REDIS_CLIENT", mock_client):
        with patch.object(soc_app, "_sse_subscribers", []) as subs:
            _sse_publish({"type": "alert", "id": 1})
    mock_client.publish.assert_called_once()
    # In-process subscribers list should not have been iterated.
    assert subs == []


# ---------------------------------------------------------------------------
# _sse_publish — in-process fallback (no Redis)
# ---------------------------------------------------------------------------

def test_sse_publish_fallback_when_no_redis_client():
    import queue
    q = queue.Queue()
    with patch.object(soc_app, "_REDIS_CLIENT", None):
        with patch.object(soc_app, "_sse_subscribers", [q]):
            _sse_publish({"type": "test"})
    assert not q.empty()
    assert q.get_nowait() == {"type": "test"}


# ---------------------------------------------------------------------------
# api_stream — Redis pubsub path (unit-level: drives the generator directly)
# ---------------------------------------------------------------------------

def _build_pubsub_mock(messages):
    """
    messages: list of dicts or None values returned by successive get_message calls.
    After the list is exhausted, raises GeneratorExit to stop the while-True loop.
    """
    counter = {"i": 0}
    items = list(messages)

    def _get_message(**kwargs):
        if counter["i"] >= len(items):
            raise GeneratorExit
        val = items[counter["i"]]
        counter["i"] += 1
        return val

    ps = MagicMock()
    ps.get_message.side_effect = _get_message
    return ps


def _stream_with_redis(mock_client, messages):
    """
    Drive the SSE generate() function with a mocked Redis pubsub.

    Flask-Login's @login_required wraps api_stream, so we use LOGIN_DISABLED to
    skip the auth redirect without touching production code or the DB.
    Returns (list_of_chunks, pubsub_mock).
    """
    ps = _build_pubsub_mock(messages)
    mock_client.pubsub.return_value = ps
    with soc_app.app.test_request_context("/stream"):
        soc_app.app.config["LOGIN_DISABLED"] = True
        try:
            with patch.object(soc_app, "_REDIS_CLIENT", mock_client):
                response = soc_app.api_stream()
                # response.response is the raw generator; iterate inside patch
                # so the closure sees _REDIS_CLIENT set.
                chunks = list(response.response)
        finally:
            soc_app.app.config["LOGIN_DISABLED"] = False
    return chunks, ps


def test_stream_redis_yields_data_line_for_alert_message():
    data_payload = json.dumps({"type": "alert", "id": 7}).encode("utf-8")
    msg = {"type": "message", "data": data_payload}
    mock_client = MagicMock()
    chunks, _ = _stream_with_redis(mock_client, [msg])
    # generator yields strings; join and check for the payload
    body = "".join(chunks)
    assert '"id": 7' in body or '"id":7' in body, chunks


def test_stream_redis_yields_keepalive_on_no_message():
    mock_client = MagicMock()
    chunks, _ = _stream_with_redis(mock_client, [None])  # None → keepalive
    body = "".join(chunks)
    assert ": keepalive" in body, chunks


def test_stream_redis_calls_unsubscribe_on_cleanup():
    mock_client = MagicMock()
    _, ps = _stream_with_redis(mock_client, [])  # empty → GeneratorExit immediately
    ps.unsubscribe.assert_called_once_with(soc_app._REDIS_SSE_CHANNEL)
    ps.close.assert_called_once()
