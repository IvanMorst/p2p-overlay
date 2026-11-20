"""Защита от повторов на прикладном уровне.

TLS 1.3 не даёт повторно отправить записанный кадр в новой сессии: ключи
сессии разные, запись не расшифруется. Дополнительно приложение ведёт учёт
идентификаторов, чтобы повтор внутри уже установленной сессии не приводил к
повторной обработке:

* ``request_id`` кадра (16 байт) — уникален для каждого запроса;
* ``session_id`` соединения — область действия учёта;
* ``message_id`` прикладного сообщения — постоянный идентификатор, который
  переживает переподключение.

Учёт ограничен по ёмкости и времени жизни: узел не хранит бесконечную историю.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(slots=True)
class ReplayGuard:
    """Ограниченный учёт ранее принятых идентификаторов."""

    capacity: int = 4096
    ttl: float = 600.0
    clock: Callable[[], float] = time.monotonic
    _seen: OrderedDict[tuple[bytes, bytes], float] = field(default_factory=OrderedDict)
    accepted: int = 0
    rejected: int = 0
    evicted: int = 0

    def accept(self, scope: bytes, identifier: bytes) -> bool:
        """``True`` — идентификатор новый, ``False`` — повтор."""
        now = self.clock()
        key = (scope, identifier)
        expires = self._seen.get(key)
        if expires is not None and expires > now:
            self.rejected += 1
            return False
        self._seen[key] = now + self.ttl
        self._seen.move_to_end(key)
        self.accepted += 1
        self._evict(now)
        return True

    def _evict(self, now: float) -> None:
        while self._seen:
            absolute = next(iter(self._seen))
            expires = self._seen[absolute]
            if expires > now and len(self._seen) <= self.capacity:
                break
            self._seen.popitem(last=False)
            self.evicted += 1

    def stats(self) -> dict[str, int]:
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "evicted": self.evicted,
            "tracked": len(self._seen),
        }
