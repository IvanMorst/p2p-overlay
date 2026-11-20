"""Итеративный поиск Kademlia с параллелизмом ``ALPHA``.

Алгоритм:

1. Инициатор формирует пул кандидатов из ближайших к цели контактов своей
   таблицы маршрутизации.
2. На каждой итерации выбираются до ``ALPHA`` ещё не опрошенных кандидатов,
   запросы уходят параллельно, ответы объединяются в пул.
3. Поиск завершается, когда все ``k`` ближайших известных кандидатов опрошены,
   либо когда очередная итерация не дала новых контактов и не осталось
   неопрошенных кандидатов, либо по достижении ``lookup_max_iterations``.
4. Тайм-аут отдельного узла не прерывает поиск: контакт помечается неудачным,
   после второго отказа удаляется из таблицы.

В журнал поиска записываются ``lookup_id``, инициатор, цель, опрошенные узлы
по итерациям, число RPC, число итераций, тайм-ауты, результат и длительность.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..config import NodeConfig
from ..errors import RoutingError, TimeoutExpired
from ..metrics import EventRecorder
from .contact import Contact
from .routing import AddResult, RoutingTable
from .rpc import DhtRpc
from .xor import distance_key

log = logging.getLogger(__name__)

_MAX_FAILURES = 2


@dataclass(slots=True)
class LookupStep:
    iteration: int
    queried: list[str]
    responded: int
    new_contacts: int
    timeouts: int
    errors: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "queried": self.queried,
            "responded": self.responded,
            "new_contacts": self.new_contacts,
            "timeouts": self.timeouts,
            "errors": self.errors,
        }


@dataclass(slots=True)
class LookupResult:
    lookup_id: str
    initiator: bytes
    target: bytes
    contacts: list[Contact]
    value: dict[str, Any] | None
    value_node: bytes | None
    iterations: int
    rpc_count: int
    timeouts: int
    errors: int
    duration_s: float
    steps: list[LookupStep] = field(default_factory=list)
    converged: bool = True
    rejected_values: int = 0

    @property
    def found(self) -> bool:
        return self.value is not None

    @property
    def contact_ids(self) -> list[bytes]:
        return [c.node_id for c in self.contacts]

    def to_dict(self) -> dict[str, Any]:
        return {
            "lookup_id": self.lookup_id,
            "initiator": self.initiator.hex(),
            "target": self.target.hex(),
            "value_found": self.found,
            "value_node": self.value_node.hex() if self.value_node else None,
            "iterations": self.iterations,
            "rpc_count": self.rpc_count,
            "timeouts": self.timeouts,
            "errors": self.errors,
            "duration_s": round(self.duration_s, 6),
            "steps": [s.to_dict() for s in self.steps],
            "result_contacts": [c.node_id.hex() for c in self.contacts],
            "converged": self.converged,
            "rejected_values": self.rejected_values,
        }


class IterativeLookup:
    """Итеративный поиск узлов и значений."""

    def __init__(
        self,
        table: RoutingTable,
        rpc: DhtRpc,
        config: NodeConfig,
        *,
        metrics: EventRecorder | None = None,
    ) -> None:
        self._table = table
        self._rpc = rpc
        self._config = config
        self._metrics = metrics
        self._failures: dict[bytes, int] = {}

    # -------------------------------------------------------------------- run

    async def run(
        self,
        target: bytes,
        *,
        want_value: bool = False,
        initial: list[Contact] | None = None,
        validator: Callable[[dict[str, Any]], Any] | None = None,
        exclude: set[bytes] | None = None,
    ) -> LookupResult:
        """Выполнить поиск узла или значения.

        ``validator`` вызывается для найденного значения; исключение означает,
        что узел вернул недействительные данные, и поиск продолжается без него.
        ``exclude`` исключает узлы из рассмотрения (например, уже отдавшие
        недействительную запись).
        """
        started = time.perf_counter()
        lookup_id = uuid.uuid4().hex
        if len(target) != len(self._table.local_id):
            raise RoutingError("target length does not match the identifier length")

        skipped = exclude or set()
        shortlist: dict[bytes, Contact] = {}
        for contact in initial if initial is not None else self._table.closest(target):
            if contact.node_id in skipped:
                continue
            shortlist.setdefault(contact.node_id, contact)
        queried: set[bytes] = set()
        steps: list[LookupStep] = []
        rpc_count = 0
        timeouts = 0
        errors = 0
        rejected_values = 0
        value: dict[str, Any] | None = None
        value_node: bytes | None = None
        converged = False

        for iteration in range(1, self._config.lookup_max_iterations + 1):
            candidates = [c for nid, c in shortlist.items() if nid not in queried]
            candidates.sort(key=lambda c: distance_key(target, c.node_id))
            batch = candidates[: self._config.alpha]
            if not batch:
                converged = True
                break
            for contact in batch:
                queried.add(contact.node_id)

            results = await asyncio.gather(
                *(self._query(contact, target, want_value) for contact in batch),
                return_exceptions=True,
            )

            new_contacts = 0
            responded = 0
            step_timeouts = 0
            step_errors = 0
            for contact, result in zip(batch, results, strict=True):
                rpc_count += 1
                if isinstance(result, TimeoutExpired):
                    step_timeouts += 1
                    timeouts += 1
                    self._note_failure(contact)
                    continue
                if isinstance(result, BaseException):
                    step_errors += 1
                    errors += 1
                    self._note_failure(contact)
                    log.debug(
                        "lookup %s: query to %s failed: %s", lookup_id, contact.short_id, result
                    )
                    continue
                responded += 1
                self._failures.pop(contact.node_id, None)
                contacts, found = result
                for candidate in contacts:
                    if candidate.node_id == self._table.local_id:
                        continue
                    if candidate.node_id in shortlist or candidate.node_id in skipped:
                        continue
                    shortlist[candidate.node_id] = candidate
                    new_contacts += 1
                self._remember(contact)
                if found is not None and value is None:
                    if validator is not None:
                        try:
                            validator(found)
                        except Exception as e:
                            rejected_values += 1
                            skipped.add(contact.node_id)
                            shortlist.pop(contact.node_id, None)
                            log.warning(
                                "lookup %s: invalid value from %s rejected: %s",
                                lookup_id,
                                contact.short_id,
                                e,
                            )
                            continue
                    value = found
                    value_node = contact.node_id

            steps.append(
                LookupStep(
                    iteration=iteration,
                    queried=[c.short_id for c in batch],
                    responded=responded,
                    new_contacts=new_contacts,
                    timeouts=step_timeouts,
                    errors=step_errors,
                )
            )

            if value is not None:
                break
            closest = self._closest_from(shortlist, target)
            if all(c.node_id in queried for c in closest):
                converged = True
                break

        closest_final = self._closest_from(shortlist, target)
        duration = time.perf_counter() - started
        result_obj = LookupResult(
            lookup_id=lookup_id,
            initiator=self._table.local_id,
            target=target,
            contacts=closest_final,
            value=value,
            value_node=value_node,
            iterations=len(steps),
            rpc_count=rpc_count,
            timeouts=timeouts,
            errors=errors,
            duration_s=duration,
            steps=steps,
            converged=converged,
            rejected_values=rejected_values,
        )
        if self._metrics is not None:
            self._metrics.emit(
                "dht.lookup",
                lookup_id=lookup_id,
                target=target.hex(),
                want_value=want_value,
                iterations=result_obj.iterations,
                rpc=result_obj.rpc_count,
                timeouts=result_obj.timeouts,
                errors=result_obj.errors,
                rejected_values=rejected_values,
                found=result_obj.found,
                duration_s=round(duration, 6),
            )
        return result_obj

    # ---------------------------------------------------------------- helpers

    async def _query(
        self, contact: Contact, target: bytes, want_value: bool
    ) -> tuple[list[Contact], dict[str, Any] | None]:
        if want_value:
            value, contacts = await self._rpc.find_value(contact, target)
            return contacts, value
        return await self._rpc.find_node(contact, target), None

    def _closest_from(self, pool: dict[bytes, Contact], target: bytes) -> list[Contact]:
        ordered = sorted(pool.values(), key=lambda c: distance_key(target, c.node_id))
        return ordered[: self._config.k_bucket_size]

    def _remember(self, contact: Contact) -> None:
        """Обновить контакт в таблице, вытеснив LRU только при необходимости."""
        outcome = self._table.add(contact)
        if outcome is AddResult.FULL:
            # Вытеснение LRU выполняет узел (нужен PING); здесь контакт просто
            # не добавляется, чтобы не терять живую запись.
            log.debug("bucket for %s is full; contact not added", contact.short_id)

    def _note_failure(self, contact: Contact) -> None:
        count = self._failures.get(contact.node_id, 0) + 1
        self._failures[contact.node_id] = count
        if count >= _MAX_FAILURES:
            self._table.remove(contact.node_id)
            self._failures.pop(contact.node_id, None)


async def lookup_node(
    table: RoutingTable, rpc: DhtRpc, config: NodeConfig, target: bytes
) -> LookupResult:
    """Удобная обёртка для одиночного поиска узла."""
    return await IterativeLookup(table, rpc, config).run(target)


__all__ = ["IterativeLookup", "LookupResult", "LookupStep", "lookup_node"]
