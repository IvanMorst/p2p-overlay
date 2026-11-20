"""Тесты k-bucket: ёмкость, LRU-порядок, вытеснение, снимки."""

from __future__ import annotations

import pytest

from overlay.dht.contact import Contact
from overlay.dht.routing import AddResult, KBucket, RoutingTable
from overlay.errors import RoutingError
from overlay.identity import Identity


def _contact(identity: Identity, port: int = 7000, host: str = "127.0.0.1") -> Contact:
    return Contact(
        node_id=identity.node_id,
        public_key_der=identity.public_key_der,
        host=host,
        port=port,
    )


def test_bucket_respects_capacity() -> None:
    bucket = KBucket(2)
    identities = [Identity.generate() for _ in range(3)]
    assert bucket.insert(_contact(identities[0])) is AddResult.ADDED
    assert bucket.insert(_contact(identities[1])) is AddResult.ADDED
    assert bucket.insert(_contact(identities[2])) is AddResult.FULL
    assert bucket.size == 2


def test_bucket_duplicate_updates_instead_of_growing() -> None:
    bucket = KBucket(2)
    identity = Identity.generate()
    bucket.insert(_contact(identity))
    assert bucket.insert(_contact(identity)) is AddResult.UPDATED
    assert bucket.size == 1


def test_bucket_lru_order_and_touch() -> None:
    bucket = KBucket(3)
    first, second, third = (Identity.generate() for _ in range(3))
    bucket.insert(_contact(first), now=1.0)
    bucket.insert(_contact(second), now=2.0)
    bucket.insert(_contact(third), now=3.0)
    assert bucket.least_recent().node_id == first.node_id
    assert bucket.most_recent().node_id == third.node_id

    assert bucket.touch(first.node_id, now=4.0) is True
    assert bucket.least_recent().node_id == second.node_id
    assert bucket.most_recent().node_id == first.node_id


def test_bucket_remove_and_clear() -> None:
    bucket = KBucket(2)
    identity = Identity.generate()
    bucket.insert(_contact(identity))
    assert bucket.remove(identity.node_id) is True
    assert bucket.remove(identity.node_id) is False
    bucket.insert(_contact(identity))
    bucket.clear()
    assert bucket.size == 0
    assert bucket.least_recent() is None


def test_routing_table_rejects_self_and_foreign_length() -> None:
    identity = Identity.generate()
    table = RoutingTable(identity.node_id, k=3)
    assert table.add(_contact(identity)) is AddResult.REJECTED_SELF

    # Контакт из другого пространства идентификаторов (64-битный) отклоняется.
    foreign = _contact(Identity.generate(node_id_bits=64))
    assert table.add(foreign) is AddResult.REJECTED_BAD_ID


def test_routing_table_closest_ordering() -> None:
    local = Identity.generate()
    table = RoutingTable(local.node_id, k=5)
    contacts = [_contact(Identity.generate(), port=7000 + i) for i in range(5)]
    for contact in contacts:
        table.add(contact)
    closest = table.closest(contacts[2].node_id, 3)
    assert closest[0].node_id == contacts[2].node_id
    assert len(closest) == 3


def test_routing_table_snapshot_has_every_bucket() -> None:
    identity = Identity.generate()
    table = RoutingTable(identity.node_id, k=3)
    table.add(_contact(Identity.generate()))
    snapshot = table.snapshot()
    assert len(snapshot) == 256
    assert sum(1 for bucket in snapshot if bucket.contacts) == 1
    stats = table.stats()
    assert stats["total_contacts"] == 1
    assert stats["k"] == 3
    assert stats["occupied_buckets"] == 1


def test_bucket_capacity_validation() -> None:
    with pytest.raises(RoutingError):
        KBucket(0)
