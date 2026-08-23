import os
import json

import pytest

from sentinellogs.detection import SecurityAlert
from sentinellogs.persistence import PostgresStore
from sentinellogs.queue import RedisQueue
from sentinellogs.schema import LogRecord


@pytest.mark.integration
def test_postgres_persistence_integration() -> None:
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("Set TEST_DATABASE_URL to run PostgreSQL integration tests")
    store = PostgresStore(dsn)
    try:
        store.save_log(LogRecord(format="integration", message="approved test event", tenant_id="integration"))
        store.save_alert(SecurityAlert("integration", "Integration", "low", "approved test alert", "integration", None, "T1078"))
    finally:
        store.close()


@pytest.mark.integration
def test_redis_queue_integration() -> None:
    if not os.environ.get("TEST_REDIS_URL"):
        pytest.skip("Set TEST_REDIS_URL to run Redis integration tests")
    queue = RedisQueue(os.environ["TEST_REDIS_URL"], name="sentinellogs:test")
    queue.client.delete(queue.name)
    received = []
    queue.publish(LogRecord(format="integration", message="approved test event", tenant_id="integration"))
    item = queue.client.blpop(queue.name, timeout=2)
    assert item is not None
    from sentinellogs.queue import record_from_payload
    received.append(record_from_payload(json.loads(item[1])))
    assert received[0].tenant_id == "integration"