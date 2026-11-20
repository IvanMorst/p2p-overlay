"""Таблица маршрутизации Kademlia: k-bucket ограниченной ёмкости с LRU.

Контакты упорядочены по времени последнего наблюдения: самый старый — первый
элемент bucket. При заполнении bucket новый контакт не вытесняет старый
немедленно: кандидат на вытеснение проверяется запросом ``PING`` (решение
принимает вызывающий код), и только недоступный LRU-контакт заменяется.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from ..errors import RoutingError
from .contact import Contact
from .xor import bucket_index, distance_key


class AddResult(Enum):
    """Исход добавления контакта в таблицу."""

    ADDED = auto()
    UPDATED = auto()
    FULL = auto()
    REJECTED_SELF = auto()
    REJECTED_BAD_ID = auto()


class KBucket:
    """Один bucket: не более ``capacity`` живых контактов в порядке LRU."""

    __slots__ = ("_capacity", "_contacts")

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise RoutingError("bucket capacity must be >= 1")
        self._capacity = capacity
        self._contacts: deque[Contact] = deque()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def size(self) -> int:
        return len(self._contacts)

    @property
    def full(self) -> bool:
        return len(self._contacts) >= self._capacity

    def contacts(self) -> list[Contact]:
        """Контакты от самого старого к самому свежему."""
        return list(self._contacts)

    def least_recent(self) -> Contact | None:
        return self._contacts[0] if self._contacts else None

    def most_recent(self) -> Contact | None:
        return self._contacts[-1] if self._contacts else None

    def get(self, node_id: bytes) -> Contact | None:
        for contact in self._contacts:
            if contact.node_id == node_id:
                return contact
        return None

    def touch(self, node_id: bytes, now: float | None = None) -> bool:
        """Отметить контакт как наблюдавшийся и переместить в свежий конец."""
        stamp = time.monotonic() if now is None else now
        for index, contact in enumerate(self._contacts):
            if contact.node_id == node_id:
                updated = contact.touch(stamp)
                del self._contacts[index]
                self._contacts.append(updated)
                return True
        return False

    def insert(self, contact: Contact, now: float | None = None) -> AddResult:
        """Добавить контакт; при заполненном bucket вернуть ``FULL``."""
        stamp = time.monotonic() if now is None else now
        existing = self.get(contact.node_id)
        if existing is not None:
            self.touch(contact.node_id, stamp)
            return AddResult.UPDATED
        if self.full:
            return AddResult.FULL
        self._contacts.append(contact.touch(stamp))
        return AddResult.ADDED

    def remove(self, node_id: bytes) -> bool:
        for index, contact in enumerate(self._contacts):
            if contact.node_id == node_id:
                del self._contacts[index]
                return True
        return False

    def clear(self) -> None:
        self._contacts.clear()

    def snapshot(self) -> list[dict[str, Any]]:
        return [c.to_public_dict() for c in self._contacts]


@dataclass(slots=True)
class BucketSnapshot:
    index: int
    capacity: int
    contacts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "capacity": self.capacity,
            "size": len(self.contacts),
            "contacts": self.contacts,
        }


class RoutingTable:
    """Набор k-bucket для ``id_bits``-битного пространства идентификаторов."""

    def __init__(self, local_id: bytes, k: int = 3) -> None:
        if not local_id:
            raise RoutingError("local_id must not be empty")
        if k < 1:
            raise RoutingError("k must be >= 1")
        self._local_id = local_id
        self._k = k
        self._id_bits = len(local_id) * 8
        self._buckets = [KBucket(k) for _ in range(self._id_bits)]

    # ------------------------------------------------------------- accessors

    @property
    def local_id(self) -> bytes:
        return self._local_id

    @property
    def k(self) -> int:
        return self._k

    @property
    def id_bits(self) -> int:
        return self._id_bits

    @property
    def buckets(self) -> list[KBucket]:
        return self._buckets

    def bucket_for(self, node_id: bytes) -> KBucket | None:
        index = bucket_index(self._local_id, node_id)
        if index is None:
            return None
        return self._buckets[index]

    # -------------------------------------------------------------- mutation

    def add(self, contact: Contact, now: float | None = None) -> AddResult:
        if contact.node_id == self._local_id:
            return AddResult.REJECTED_SELF
        if len(contact.node_id) != len(self._local_id):
            return AddResult.REJECTED_BAD_ID
        bucket = self.bucket_for(contact.node_id)
        assert bucket is not None
        return bucket.insert(contact, now)

    def touch(self, node_id: bytes, now: float | None = None) -> bool:
        bucket = self.bucket_for(node_id)
        if bucket is None:
            return False
        return bucket.touch(node_id, now)

    def remove(self, node_id: bytes) -> bool:
        bucket = self.bucket_for(node_id)
        if bucket is None:
            return False
        return bucket.remove(node_id)

    def clear(self) -> None:
        for bucket in self._buckets:
            bucket.clear()

    # --------------------------------------------------------------- queries

    def get(self, node_id: bytes) -> Contact | None:
        bucket = self.bucket_for(node_id)
        if bucket is None:
            return None
        return bucket.get(node_id)

    def all_contacts(self) -> list[Contact]:
        result: list[Contact] = []
        for bucket in self._buckets:
            result.extend(bucket.contacts())
        return result

    def __len__(self) -> int:
        return sum(bucket.size for bucket in self._buckets)

    def __contains__(self, node_id: object) -> bool:
        return isinstance(node_id, bytes) and self.get(node_id) is not None

    def closest(self, target: bytes, count: int | None = None) -> list[Contact]:
        """До ``count`` контактов в порядке возрастания XOR-расстояния."""
        limit = self._k if count is None else count
        contacts = self.all_contacts()
        contacts.sort(key=lambda c: distance_key(target, c.node_id))
        return contacts[:limit]

    def closest_excluding(
        self, target: bytes, exclude: set[bytes], count: int | None = None
    ) -> list[Contact]:
        limit = self._k if count is None else count
        contacts = [c for c in self.all_contacts() if c.node_id not in exclude]
        contacts.sort(key=lambda c: distance_key(target, c.node_id))
        return contacts[:limit]

    def needs_refresh(self, interval: float, now: float | None = None) -> list[int]:
        """Индексы bucket, которые давно не обновлялись."""
        stamp = time.monotonic() if now is None else now
        stale: list[int] = []
        for index, bucket in enumerate(self._buckets):
            recent = bucket.most_recent()
            if recent is None:
                continue
            if stamp - recent.last_seen >= interval:
                stale.append(index)
        return stale

    # ------------------------------------------------------------- snapshots

    def snapshot(self) -> list[BucketSnapshot]:
        """Содержимое каждого bucket отдельно (требование раздела 10.1 ТЗ)."""
        return [
            BucketSnapshot(index=i, capacity=b.capacity, contacts=b.snapshot())
            for i, b in enumerate(self._buckets)
        ]

    def bucket_table(self) -> list[dict[str, Any]]:
        return [b.to_dict() for b in self.snapshot()]

    def stats(self) -> dict[str, Any]:
        sizes = [bucket.size for bucket in self._buckets]
        occupied = sum(1 for size in sizes if size > 0)
        return {
            "total_contacts": sum(sizes),
            "k": self._k,
            "id_bits": self._id_bits,
            "buckets": len(self._buckets),
            "occupied_buckets": occupied,
            "empty_buckets": len(self._buckets) - occupied,
            "max_bucket_fill": max(sizes) if sizes else 0,
            "full_buckets": sum(1 for size in sizes if size >= self._k),
            "bucket_sizes": {i: size for i, size in enumerate(sizes) if size},
        }
