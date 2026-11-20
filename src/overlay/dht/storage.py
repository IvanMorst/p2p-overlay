"""Локальное хранилище записей DHT с TTL и защитой от отката версии.

Хранилище отвечает за три вещи:

* приём записи только после полной проверки (см. ``dht.record``);
* отказ от записи с меньшим или равным ``sequence_number``, если содержимое
  отличается, — защита от отката версии;
* удаление записей по истечении TTL.

Состояние может сохраняться в файл каталога состояния узла, чтобы запись
переживала перезапуск процесса.
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import NodeConfig
from ..errors import RecordError
from ..transport import codec
from .record import NodeRecord, StaleRecord, parse_record, validate_record

log = logging.getLogger(__name__)


@dataclass(slots=True)
class StoreOutcome:
    """Результат попытки сохранения."""

    accepted: bool
    reason: str = "ok"
    sequence_number: int = 0

    def to_cbor(self) -> dict[str, Any]:
        return {
            "stored": self.accepted,
            "reason": self.reason,
            "sequence_number": self.sequence_number,
        }


@dataclass(slots=True)
class RecordStore:
    """Записи, принятые этим узлом в качестве хранителя."""

    config: NodeConfig
    path: Path | None = None
    clock: Callable[[], float] = time.time
    _records: dict[bytes, NodeRecord] = field(default_factory=dict)
    _accepted: int = 0
    _rejected: int = 0
    _expired: int = 0

    # ------------------------------------------------------------- lifecycle

    def load(self) -> int:
        """Загрузить сохранённые записи; истёкшие отбрасываются."""
        if self.path is None or not self.path.exists():
            return 0
        try:
            payload = codec.decode_payload(self.path.read_bytes())
        except Exception as e:
            log.warning("cannot read %s: %s", self.path, e)
            return 0
        loaded = 0
        now = self.clock()
        for item in payload.get("records", []):
            try:
                record = parse_record(item)
                validate_record(record, self.config, now=now)
            except RecordError as e:
                log.debug("dropping stored record: %s", e)
                continue
            self._records[record.record_key] = record
            loaded += 1
        self._purge(now)
        log.info("loaded %d records from %s", loaded, self.path)
        return loaded

    def save(self) -> None:
        """Атомарно записать состояние на диск."""
        if self.path is None:
            return
        payload = {"version": 1, "records": [r.to_cbor() for r in self._records.values()]}
        data = codec.encode_payload(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, self.path)

    # ----------------------------------------------------------------- write

    def put(self, record: NodeRecord) -> StoreOutcome:
        """Проверить и сохранить запись."""
        now = self.clock()
        try:
            validate_record(record, self.config, now=now)
        except RecordError as e:
            self._rejected += 1
            return StoreOutcome(False, f"{type(e).__name__}: {e}", record.sequence_number)

        key = record.record_key
        existing = self._records.get(key)
        if existing is not None:
            if record.sequence_number < existing.sequence_number:
                self._rejected += 1
                return StoreOutcome(
                    False,
                    f"StaleRecord: sequence {record.sequence_number} < "
                    f"{existing.sequence_number}",
                    existing.sequence_number,
                )
            if record.sequence_number == existing.sequence_number:
                if record.signature == existing.signature:
                    return StoreOutcome(True, "duplicate", existing.sequence_number)
                self._rejected += 1
                return StoreOutcome(
                    False,
                    "StaleRecord: same sequence_number with different content",
                    existing.sequence_number,
                )

        self._records[key] = record
        self._accepted += 1
        return StoreOutcome(True, "stored", record.sequence_number)

    def put_or_raise(self, record: NodeRecord) -> None:
        outcome = self.put(record)
        if not outcome.accepted:
            raise StaleRecord(outcome.reason)

    # ------------------------------------------------------------------ read

    def get(self, key: bytes) -> NodeRecord | None:
        record = self._records.get(key)
        if record is None:
            return None
        if record.is_expired(self.clock()):
            del self._records[key]
            self._expired += 1
            return None
        return record

    def get_by_node(self, node_id: bytes) -> NodeRecord | None:
        from .record import record_key_for_node

        return self.get(record_key_for_node(node_id))

    def delete(self, key: bytes) -> bool:
        """Удалить запись из локального хранилища (например, при отказе)."""
        return self._records.pop(key, None) is not None

    def keys(self) -> list[bytes]:
        self._purge(self.clock())
        return list(self._records)

    def records(self) -> list[NodeRecord]:
        self._purge(self.clock())
        return list(self._records.values())

    def sequence_for(self, node_id: bytes) -> int:
        """Наибольший известный номер версии записи узла."""
        record = self.get_by_node(node_id)
        return record.sequence_number if record is not None else 0

    def __len__(self) -> int:
        self._purge(self.clock())
        return len(self._records)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, bytes) and self.get(key) is not None

    # -------------------------------------------------------------- обслужив.

    def purge_expired(self) -> int:
        return self._purge(self.clock())

    def _purge(self, now: float) -> int:
        expired = [key for key, record in self._records.items() if record.expires_at <= now]
        for key in expired:
            del self._records[key]
        self._expired += len(expired)
        return len(expired)

    def stats(self) -> dict[str, Any]:
        now = self.clock()
        records = list(self._records.values())
        return {
            "records": len(records),
            "accepted": self._accepted,
            "rejected": self._rejected,
            "expired": self._expired,
            "oldest_age_s": round(max((now - r.issued_at for r in records), default=0.0), 3),
            "min_ttl_left_s": round(
                min((r.expires_at - now for r in records), default=0.0), 3
            ),
        }

    def snapshot(self) -> list[dict[str, Any]]:
        now = self.clock()
        return [
            {
                "node_id": record.node_id.hex(),
                "key": record.record_key.hex(),
                "sequence_number": record.sequence_number,
                "addresses": [str(a) for a in record.addresses],
                "issued_at": record.issued_at,
                "expires_at": record.expires_at,
                "ttl_left_s": round(record.expires_at - now, 3),
            }
            for record in sorted(self._records.values(), key=lambda r: r.node_id)
        ]


def load_store(config: NodeConfig, *, path: Path | None = None) -> RecordStore:
    """Создать хранилище и загрузить сохранённое состояние."""
    store = RecordStore(config=config, path=path if path is not None else config.storage_path)
    with contextlib.suppress(Exception):
        store.load()
    return store
