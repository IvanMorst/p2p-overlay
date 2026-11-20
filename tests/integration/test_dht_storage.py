"""Интеграционные тесты хранения DHT: STORE, FIND_VALUE, репликация, отказ."""

from __future__ import annotations

from dataclasses import replace

import pytest

from overlay.dht.record import Address, NodeRecord, record_key_for_node
from tests.lab import Lab, LabParams, make_lab


@pytest.fixture
async def storage_lab(tmp_path) -> Lab:
    stand = make_lab(tmp_path, LabParams(n=7))
    await stand.start()
    try:
        yield stand
    finally:
        await stand.stop()


async def test_join_publishes_own_record(storage_lab: Lab) -> None:
    node = storage_lab.node(3)
    key = record_key_for_node(node.node_id)
    record = node.storage.get(key)
    assert record is not None
    assert record.node_id == node.node_id
    assert record.sequence_number >= 1


async def test_publish_reports_replication_acks(storage_lab: Lab) -> None:
    node = storage_lab.node(2)
    report = await node.publish_self()
    assert report.success is True
    assert report.acks >= node.config.store_success_acks
    assert report.local is True


async def test_record_is_replicated_to_three_holders(storage_lab: Lab) -> None:
    owner = storage_lab.node(1)
    key = record_key_for_node(owner.node_id)
    # Публикация после сходимости сети: к этому моменту известны все кандидаты.
    report = await owner.publish_self()
    assert report.success
    holders = [i for i in storage_lab.active if storage_lab.node(i).storage.get(key) is not None]
    assert len(holders) >= owner.config.replication_factor


async def test_find_value_from_node_without_local_copy(storage_lab: Lab) -> None:
    owner = storage_lab.node(2)
    seeker = storage_lab.node(5)
    key = record_key_for_node(owner.node_id)
    seeker.storage.delete(key)
    assert seeker.storage.get(key) is None

    record = await seeker.get_record(key)

    assert record is not None
    assert record.node_id == owner.node_id
    assert record.sequence_number >= 1


async def test_find_value_survives_holder_failure(storage_lab: Lab) -> None:
    """Контрольный результат этапа 3: запись читается после отказа хранителя."""
    owner = storage_lab.node(2)
    key = record_key_for_node(owner.node_id)
    holders = [i for i in storage_lab.active if storage_lab.node(i).storage.get(key) is not None]
    assert len(holders) >= 3

    seeker = next(i for i in storage_lab.active if i not in holders)
    await storage_lab.stop_node(holders[0])

    record = await storage_lab.node(seeker).get_record(key)

    assert record is not None
    assert record.node_id == owner.node_id


async def test_rollback_is_rejected_by_holder(storage_lab: Lab) -> None:
    owner = storage_lab.node(1)
    holder = storage_lab.node(0)
    key = record_key_for_node(owner.node_id)
    current = owner.storage.get_by_node(owner.node_id)
    assert current is not None
    rolled_back = NodeRecord.create(
        owner.identity,
        [Address("127.0.0.1", owner.bound_port)],
        sequence_number=max(0, current.sequence_number - 1),
        ttl_seconds=owner.config.record_ttl_seconds,
    )
    stored = await owner.rpc.store(holder.peers.local_contact, key, rolled_back.to_cbor())

    assert stored is False
    assert holder.storage.get(key).sequence_number >= current.sequence_number


async def test_forged_record_is_rejected_by_holder(storage_lab: Lab) -> None:
    owner = storage_lab.node(1)
    holder = storage_lab.node(0)
    attacker = storage_lab.node(4)
    key = record_key_for_node(owner.node_id)
    forged = NodeRecord.create(
        attacker.identity,
        [Address("127.0.0.1", attacker.bound_port)],
        sequence_number=999,
        ttl_seconds=owner.config.record_ttl_seconds,
    )
    forged_map = dict(forged.to_cbor())
    forged_map["node_id"] = owner.node_id  # подмена владельца при чужой подписи

    stored = await owner.rpc.store(holder.peers.local_contact, key, forged_map)

    assert stored is False


async def test_store_rejects_key_mismatch(storage_lab: Lab) -> None:
    owner = storage_lab.node(1)
    holder = storage_lab.node(0)
    record = owner.build_self_record()
    wrong_key = record_key_for_node(storage_lab.node(3).node_id)

    stored = await owner.rpc.store(holder.peers.local_contact, wrong_key, record.to_cbor())

    assert stored is False


async def test_resolve_contact_uses_signed_record(storage_lab: Lab) -> None:
    target = storage_lab.node(4)
    seeker = storage_lab.node(6)
    seeker.table.remove(target.node_id)
    seeker.storage.delete(record_key_for_node(target.node_id))

    contact = await seeker.resolve_contact(target.node_id)

    assert contact.node_id == target.node_id
    assert contact.port == target.bound_port
    assert await seeker.rpc.ping(contact) is True


async def test_republish_increments_sequence(tmp_path) -> None:
    """Переопубликование повышает sequence_number и обновляет TTL."""
    stand = make_lab(
        tmp_path,
        LabParams(
            n=4,
            record_ttl_seconds=20,
            request_timeout=2.0,
            connect_timeout=2.0,
        ),
    )
    await stand.start()
    try:
        node = stand.node(1)
        first = node.storage.get_by_node(node.node_id)
        assert first is not None
        report = await node.publish_self()
        second = node.storage.get_by_node(node.node_id)
        assert report.success
        assert second is not None
        assert second.sequence_number > first.sequence_number
        assert second.expires_at >= first.expires_at
    finally:
        await stand.stop()


async def test_record_expiry_stops_serving(tmp_path) -> None:
    """Истёкшая запись не выдаётся хранилищем и не находится поиском."""
    stand = make_lab(
        tmp_path,
        LabParams(n=4, record_ttl_seconds=10, request_timeout=2.0, connect_timeout=2.0),
    )
    await stand.start()
    try:
        owner = stand.node(2)
        key = record_key_for_node(owner.node_id)
        record = owner.storage.get(key)
        assert record is not None
        # Сдвигаем срок действия в прошлое у всех хранителей.
        expired = replace(record, expires_at=int(record.issued_at))
        for index in stand.active:
            storage = stand.node(index).storage
            if storage.get(key) is not None:
                storage._records[key] = expired
        assert owner.storage.get(key) is None
    finally:
        await stand.stop()
