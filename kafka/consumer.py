"""Kafka consumer: subscribe to the 'incidents' topic and ingest into SOC-Dashboard."""
import json
import logging
import threading
from typing import Callable

from confluent_kafka import Consumer, KafkaError

logger = logging.getLogger(__name__)

TOPIC = "incidents"
GROUP_ID = "soc-dashboard"


class KafkaAlertConsumer:
    """Background thread that consumes Kafka incident messages and ingests them
    by calling an injected ingest function — no dependency on Flask request context.

    The ingest_fn receives the decoded message body as a plain dict. It is
    responsible for validation, DB insertion, and SSE broadcast. Any exception
    it raises is caught and logged; the consumer loop continues.
    """

    def __init__(
        self,
        broker: str,
        ingest_fn: Callable[[dict], None],
        topic: str = TOPIC,
    ) -> None:
        self._broker = broker
        self._ingest_fn = ingest_fn
        self._topic = topic
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="kafka-consumer"
        )

    def start(self) -> None:
        """Start the consumer background thread."""
        self._thread.start()
        logger.info(
            "Kafka consumer started (broker=%s topic=%s group=%s)",
            self._broker, self._topic, GROUP_ID,
        )

    def stop(self) -> None:
        """Signal the consumer loop to exit on its next poll cycle."""
        self._stop.set()

    def _run(self) -> None:
        consumer = Consumer({
            "bootstrap.servers": self._broker,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
        })
        consumer.subscribe([self._topic])
        try:
            while not self._stop.is_set():
                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error("Kafka consumer error: %s", msg.error())
                    continue
                self._handle(msg)
        finally:
            consumer.close()

    def _handle(self, msg) -> None:
        """Decode and ingest one Kafka message, logging on any failure."""
        try:
            body = json.loads(msg.value().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning(
                "Kafka: skipping malformed message at %s[%d]@%d: %s",
                msg.topic(), msg.partition(), msg.offset(), exc,
            )
            return
        if not isinstance(body, dict):
            logger.warning("Kafka: skipping non-dict message body")
            return
        try:
            self._ingest_fn(body)
        except Exception as exc:
            logger.error(
                "Kafka: ingest failed for message at %s[%d]@%d: %s",
                msg.topic(), msg.partition(), msg.offset(), exc,
            )
