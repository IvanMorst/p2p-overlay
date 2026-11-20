"""События и метрики узла.

Все измерения пишутся в машиночитаемый JSONL-журнал: одна строка — одно
событие. Из этих файлов скрипты обработки строят таблицы и графики, поэтому
графики всегда подтверждаются сырыми данными (требование раздела 15.3 ТЗ).
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter, deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Event:
    ts: float
    kind: str
    node: str
    fields: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ts": round(self.ts, 6), "kind": self.kind, "node": self.node}
        payload.update(self.fields)
        return payload


class EventRecorder:
    """Сбор событий узла в память и, при необходимости, в JSONL-файл."""

    def __init__(
        self,
        *,
        node_id: str,
        run_id: str = "run",
        directory: Path | None = None,
        enabled: bool = True,
        memory_limit: int = 5000,
    ) -> None:
        self.node_id = node_id
        self.run_id = run_id
        self.enabled = enabled
        self._events: deque[Event] = deque(maxlen=memory_limit)
        self._counters: Counter[str] = Counter()
        self._path: Path | None = None
        self._handle: Any = None
        self._started = time.time()
        if enabled and directory is not None:
            self._path = Path(directory) / run_id / f"node-{node_id[:12]}.jsonl"
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = self._path.open("a", encoding="utf-8")

    # ------------------------------------------------------------------ write

    def emit(self, kind: str, **fields: Any) -> None:
        if not self.enabled:
            return
        event = Event(ts=time.time() - self._started, kind=kind, node=self.node_id, fields=fields)
        self._events.append(event)
        self._counters[kind] += 1
        if self._handle is not None:
            try:
                self._handle.write(json.dumps(event.to_json(), ensure_ascii=False, default=str))
                self._handle.write("\n")
                self._handle.flush()
            except Exception:  # журнал не должен ронять узел
                log.exception("failed to write metrics event")

    def count(self, name: str, value: int = 1) -> None:
        self._counters[name] += value

    # ------------------------------------------------------------------ read

    @property
    def path(self) -> Path | None:
        return self._path

    def counters(self) -> dict[str, int]:
        return dict(self._counters)

    def recent(self, kind: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        items = list(self._events)
        if kind is not None:
            items = [e for e in items if e.kind == kind]
        return [e.to_json() for e in items[-limit:]]

    def snapshot(self) -> dict[str, Any]:
        return {
            "node": self.node_id,
            "run_id": self.run_id,
            "events": len(self._events),
            "counters": dict(self._counters),
            "log_path": str(self._path) if self._path else None,
        }

    # --------------------------------------------------------------- timing

    @contextmanager
    def timed(self, kind: str, **fields: Any) -> Iterator[dict[str, Any]]:
        """Измерить длительность операции и записать событие."""
        started = time.perf_counter()
        extra: dict[str, Any] = {}
        try:
            yield extra
        finally:
            duration = time.perf_counter() - started
            merged = {**fields, **extra, "duration_s": round(duration, 6)}
            self.emit(kind, **merged)

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            finally:
                self._handle = None
