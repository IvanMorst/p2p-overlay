"""Тесты локального хранилища записей: TTL, откат версии, персистентность."""

from __future__ import annotations

from pathlib import Path

import pytest

from overlay.config import NodeConfig
from overlay.dht.record import Address, NodeRecord, StaleRecord
from overlay.dht.storage import RecordStore
from overlay.identity import Identity

CONFIG = NodeConfig()


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _store(tmp_path: Path | None = None, clock: FakeClock | None = None) -> RecordStore:
    return RecordStore(
        config=CONFIG,
        path=(tmp_path / "dht.cbor") if tmp_path is not None else None,
        clock=clock or FakeClock(),
    )


def _record(identity: Identity, sequence: int, *, clock: FakeClock, ttl: int = 120) -> NodeRecord:
    return NodeRecord.create(
        identity,
        [Address("127.0.0.1", 7000)],
        sequence_number=sequence,
        ttl_seconds=ttl,
        now=clock(),
    )


def test_store_accepts_and_returns_record() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    record = _record(identity, 1, clock=clock)
    outcome = store.put(record)
    assert outcome.accepted
    assert outcome.reason == "stored"
    assert store.get(record.record_key) == record
    assert len(store) == 1


def test_store_accepts_duplicate_identical_record() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    record = _record(identity, 1, clock=clock)
    store.put(record)
    outcome = store.put(record)
    assert outcome.accepted
    assert outcome.reason == "duplicate"


def test_store_rejects_rollback() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    newer = _record(identity, 5, clock=clock)
    older = _record(identity, 3, clock=clock)
    assert store.put(newer).accepted
    outcome = store.put(older)
    assert not outcome.accepted
    assert "StaleRecord" in outcome.reason
    assert store.get(newer.record_key) == newer


def test_store_rejects_same_sequence_with_different_content() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    first = _record(identity, 5, clock=clock)
    second = NodeRecord.create(
        identity,
        [Address("127.0.0.1", 7001)],
        sequence_number=5,
        ttl_seconds=120,
        now=clock(),
    )
    assert store.put(first).accepted
    outcome = store.put(second)
    assert not outcome.accepted
    assert "different content" in outcome.reason


def test_store_accepts_newer_sequence() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    assert store.put(_record(identity, 1, clock=clock)).accepted
    clock.advance(1)
    newer = _record(identity, 2, clock=clock)
    assert store.put(newer).accepted
    assert store.get(newer.record_key).sequence_number == 2


def test_store_drops_expired_records() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    record = _record(identity, 1, clock=clock, ttl=120)
    store.put(record)
    assert store.get(record.record_key) is not None
    clock.advance(121)
    assert store.get(record.record_key) is None
    assert len(store) == 0
    assert store.stats()["expired"] >= 1


def test_store_rejects_expired_on_put() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    record = _record(identity, 1, clock=clock, ttl=120)
    clock.advance(200)
    outcome = store.put(record)
    assert not outcome.accepted
    assert "ExpiredRecord" in outcome.reason


def test_store_persists_across_instances(tmp_path: Path) -> None:
    clock = FakeClock()
    identity = Identity.generate()
    first = _store(tmp_path, clock=clock)
    record = _record(identity, 1, clock=clock)
    first.put(record)
    first.save()

    second = _store(tmp_path, clock=clock)
    assert second.load() == 1
    assert second.get(record.record_key) == record


def test_store_purge_on_load_drops_expired(tmp_path: Path) -> None:
    clock = FakeClock()
    identity = Identity.generate()
    first = _store(tmp_path, clock=clock)
    first.put(_record(identity, 1, clock=clock, ttl=120))
    first.save()
    clock.advance(500)
    second = _store(tmp_path, clock=clock)
    assert second.load() == 0


def test_store_sequence_lookup() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    assert store.sequence_for(identity.node_id) == 0
    store.put(_record(identity, 7, clock=clock))
    assert store.sequence_for(identity.node_id) == 7


def test_put_or_raise() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    store.put(_record(identity, 5, clock=clock))
    with pytest.raises(StaleRecord):
        store.put_or_raise(_record(identity, 4, clock=clock))


def test_store_stats_and_snapshot() -> None:
    clock = FakeClock()
    store = _store(clock=clock)
    identity = Identity.generate()
    store.put(_record(identity, 3, clock=clock))
    stats = store.stats()
    assert stats["records"] == 1
    assert stats["accepted"] == 1
    snapshot = store.snapshot()
    assert snapshot[0]["sequence_number"] == 3
    assert snapshot[0]["addresses"] == ["127.0.0.1:7000"]
