"""Unit tests for kafka/consumer.py (no broker required)."""
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kafka.consumer import GROUP_ID, TOPIC, KafkaAlertConsumer


def _make_msg(body, error=None):
    """Build a mock confluent-kafka Message for a given body dict."""
    msg = MagicMock()
    msg.error.return_value = error
    msg.value.return_value = json.dumps(body).encode("utf-8")
    msg.topic.return_value = TOPIC
    msg.partition.return_value = 0
    msg.offset.return_value = 0
    return msg


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_thread_is_daemon():
    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=MagicMock())
    assert consumer._thread.daemon is True


def test_thread_name():
    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=MagicMock())
    assert consumer._thread.name == "kafka-consumer"


def test_custom_topic_stored():
    consumer = KafkaAlertConsumer(
        "localhost:9092", ingest_fn=MagicMock(), topic="custom_topic"
    )
    assert consumer._topic == "custom_topic"


# ---------------------------------------------------------------------------
# _handle — happy path
# ---------------------------------------------------------------------------

def test_handle_calls_ingest_fn_with_decoded_body():
    ingest_fn = MagicMock()
    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=ingest_fn)
    body = {"title": "Brute force from 1.2.3.4", "category": "brute_force", "severity": "HIGH"}
    consumer._handle(_make_msg(body))
    ingest_fn.assert_called_once_with(body)


# ---------------------------------------------------------------------------
# _handle — malformed / invalid input
# ---------------------------------------------------------------------------

def test_handle_skips_malformed_json():
    ingest_fn = MagicMock()
    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=ingest_fn)
    msg = MagicMock()
    msg.error.return_value = None
    msg.value.return_value = b"not-valid-json{{{{"
    msg.topic.return_value = TOPIC
    msg.partition.return_value = 0
    msg.offset.return_value = 0
    consumer._handle(msg)
    ingest_fn.assert_not_called()


def test_handle_skips_non_dict_body():
    ingest_fn = MagicMock()
    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=ingest_fn)
    msg = MagicMock()
    msg.error.return_value = None
    msg.value.return_value = json.dumps(["not", "a", "dict"]).encode()
    msg.topic.return_value = TOPIC
    msg.partition.return_value = 0
    msg.offset.return_value = 0
    consumer._handle(msg)
    ingest_fn.assert_not_called()


def test_handle_does_not_raise_on_ingest_exception():
    """ingest_fn failures must not crash the consumer loop."""
    def boom(body):
        raise RuntimeError("db is down")

    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=boom)
    consumer._handle(_make_msg({"title": "x", "category": "y", "severity": "LOW"}))


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------

def test_stop_sets_event():
    consumer = KafkaAlertConsumer("localhost:9092", ingest_fn=MagicMock())
    assert not consumer._stop.is_set()
    consumer.stop()
    assert consumer._stop.is_set()
