"""Узел оверлейной сети: связывание подсистем и публичный фасад.

Фасад (раздел 7 ТЗ) — единственная точка, через которую прикладной слой
обращается к DHT и туннелям::

    join(bootstrap_peers)
    lookup_node(target_node_id)
    put_record(key, signed_record, ttl)
    get_record(key)
    build_tunnel(destination_node_id, constraints)
    send_via_tunnel(tunnel_id, payload)
    close_tunnel(tunnel_id)
    get_network_state()

Прикладной слой не имеет доступа к k-bucket и локальному хранилищу: они живут
внутри узла и отдаются наружу только через эти методы.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from dataclasses import dataclass
from typing import Any

from .app.messages import MessageRecord, MessageService
from .config import NodeConfig, PeerAddress
from .control import ControlServer
from .dht.contact import Contact
from .dht.lookup import IterativeLookup, LookupResult
from .dht.record import (
    Address,
    NodeRecord,
    parse_record,
    record_key_for_node,
    validate_record,
)
from .dht.routing import AddResult, KBucket, RoutingTable
from .dht.rpc import DhtRpc
from .dht.service import DhtService
from .dht.storage import RecordStore, load_store
from .errors import HandshakeError, RecordError, TunnelError
from .identity import Identity
from .metrics import EventRecorder
from .peers import PeerManager
from .security import SecurityLayer, build_security
from .transport.frame import Frame
from .transport.tcp import Connection, serve
from .tunnel.manager import TUNNEL_MESSAGES, Tunnel, TunnelManager

log = logging.getLogger(__name__)

_REFRESH_TICK = 1.0


@dataclass(slots=True)
class JoinReport:
    """Результат присоединения к сети."""

    bootstrapped: int
    failed: list[str]
    contacts_after: int
    duration_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "bootstrapped": self.bootstrapped,
            "failed": list(self.failed),
            "contacts_after": self.contacts_after,
            "duration_s": round(self.duration_s, 6),
        }


@dataclass(slots=True)
class PublishResult:
    """Результат публикации записи DHT."""

    record_key: bytes
    sequence_number: int
    local: bool
    acks: int
    holders: list[str]
    success: bool
    duration_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_key": self.record_key.hex(),
            "sequence_number": self.sequence_number,
            "local_stored": self.local,
            "acks": self.acks,
            "holders": list(self.holders),
            "success": self.success,
            "duration_s": round(self.duration_s, 6),
        }


class Node:
    """Узел оверлейной сети с DHT и (по мере готовности) туннелями."""
    def __init__(
        self,
        config: NodeConfig,
        *,
        identity: Identity | None = None,
        metrics: EventRecorder | None = None,
    ) -> None:
        self.config = config
        self.identity = identity or Identity.load_or_create(
            config.identity_dir, config.node_id_bits
        )
        self.metrics = metrics or EventRecorder(
            node_id=self.identity.node_id.hex(),
            run_id=config.metrics_run_id,
            directory=config.metrics_dir if config.metrics_enabled else None,
            enabled=config.metrics_enabled,
        )
        self.security: SecurityLayer = build_security(self.identity, config)
        self.table = RoutingTable(self.identity.node_id, config.k_bucket_size)
        self.peers = PeerManager(self.identity, config, self.security, metrics=self.metrics)
        self.peers.set_dispatcher(self._on_frame)
        self.rpc = DhtRpc(self.peers, config, metrics=self.metrics)
        self.lookup = IterativeLookup(self.table, self.rpc, config, metrics=self.metrics)
        self.storage: RecordStore = load_store(config)
        self.service = DhtService(
            self.identity, self.table, config, storage=self.storage, metrics=self.metrics
        )
        self.tunnels = TunnelManager(self)
        self.messages = MessageService(self)
        self._rng = random.Random(config.random_seed or None)
        self._published_once = False
        self._server: asyncio.Server | None = None
        self.control: ControlServer | None = None
        self._inbound: set[Connection] = set()
        self._background: list[asyncio.Task[None]] = []
        self._started_at = 0.0
        self._stopping = False
        self.bound_port = config.listen_port

    # ------------------------------------------------------------- properties

    @property
    def node_id(self) -> bytes:
        return self.identity.node_id

    @property
    def node_id_hex(self) -> str:
        return self.identity.node_id.hex()

    @property
    def address(self) -> str:
        return self.peers.local_contact.address

    @property
    def running(self) -> bool:
        return self._server is not None and not self._stopping

    # -------------------------------------------------------------- lifecycle

    async def start(self, *, background: bool = False) -> None:
        """Запустить прослушивание TCP и, при необходимости, фоновые задачи."""
        if self._server is not None:
            return
        self._server = await serve(
            self.config.listen_host,
            self.config.listen_port,
            self._on_connection,
            ssl_context=self.security.server_context(),
            handshake_timeout=self.config.handshake_timeout_seconds,
            request_timeout=self.config.request_timeout_seconds,
        )
        sockets = self._server.sockets
        if sockets:
            self.bound_port = int(sockets[0].getsockname()[1])
        self.peers.set_bound_port(self.bound_port)
        if self.config.control_port:
            self.control = ControlServer(
                self, self.config.control_host, self.config.control_port
            )
            await self.control.start()
        self._started_at = time.time()
        self.metrics.emit(
            "node.start",
            port=self.bound_port,
            node_id_bits=self.config.node_id_bits,
            k=self.config.k_bucket_size,
            alpha=self.config.alpha,
            security=self.security.describe(),
            listen_host=self.config.listen_host,
        )
        if background:
            self.start_background()
    def start_background(self) -> None:
        """Запустить refresh, обслуживание записей DHT и контроль туннелей."""
        if self._background:
            return
        self._background.append(asyncio.create_task(self._refresh_loop(), name="dht-refresh"))
        self._background.append(
            asyncio.create_task(self._maintenance_loop(), name="dht-maintenance")
        )
        self.tunnels.start()

    async def stop(self) -> None:
        """Остановить узел: фоновые задачи, соединения, сервер."""
        self._stopping = True
        for task in self._background:
            task.cancel()
        for task in self._background:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._background.clear()
        if self.control is not None:
            await self.control.stop()
            self.control = None
        await self.tunnels.stop()
        await self.peers.close_all()
        with contextlib.suppress(Exception):
            self.storage.save()
        inbound = list(self._inbound)
        self._inbound.clear()
        await asyncio.gather(*(c.close() for c in inbound), return_exceptions=True)
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        self.metrics.emit("node.stop", contacts=len(self.table))
        self.metrics.close()

    async def __aenter__(self) -> Node:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # ------------------------------------------------------------- networking

    async def _on_connection(self, conn: Connection) -> None:
        holder: dict[str, Contact] = {}
        self._inbound.add(conn)

        async def handler(frame: Frame) -> None:
            await self._on_frame(conn, holder.get("peer"), frame)

        try:
            peer = await self.peers.accept(conn, handler)
        except HandshakeError as e:
            log.warning("incoming connection rejected: %s", e)
            self._inbound.discard(conn)
            await conn.close()
            return
        holder["peer"] = peer
        await self._learn(peer)
        try:
            await conn.wait_closed()
        finally:
            # Закрытие соединения не означает отказ узла: контакт остаётся в
            # таблице и вытесняется только после неудачных PING или по LRU.
            self._inbound.discard(conn)

    async def _on_frame(self, conn: Connection, peer: Contact | None, frame: Frame) -> None:
        if frame.type in TUNNEL_MESSAGES:
            await self.tunnels.handle(conn, peer, frame)
            return
        await self.service.handle(conn, peer, frame)

    async def _learn(self, contact: Contact) -> AddResult:
        """Добавить контакт в таблицу; при полном bucket проверить LRU."""
        outcome = self.table.add(contact)
        if outcome is not AddResult.FULL:
            return outcome
        bucket: KBucket | None = self.table.bucket_for(contact.node_id)
        lru = bucket.least_recent() if bucket is not None else None
        if bucket is None or lru is None:
            return AddResult.FULL
        alive = await self.rpc.ping(lru)
        if alive:
            # Живой LRU-контакт сохраняется, новый кандидат отбрасывается.
            bucket.touch(lru.node_id)
            self.metrics.emit(
                "dht.lru_kept", kept=lru.short_id, candidate=contact.short_id
            )
            return AddResult.FULL
        bucket.remove(lru.node_id)
        self.peers.forget(lru.node_id)
        self.metrics.emit("dht.lru_evicted", evicted=lru.short_id, added=contact.short_id)
        replacement = self.table.add(contact)
        return replacement

    # ------------------------------------------------------------------- join

    async def join(self, bootstrap: list[PeerAddress] | None = None) -> JoinReport:
        """Присоединиться к сети: bootstrap, затем self-lookup."""
        started = time.perf_counter()
        addresses = list(bootstrap if bootstrap is not None else self.config.bootstrap_peers)
        bootstrapped = 0
        failed: list[str] = []
        for address in addresses:
            try:
                _conn, contact = await self.peers.dial_address(address.host, address.port)
                await self._learn(contact)
                bootstrapped += 1
            except Exception as e:
                failed.append(f"{address}: {type(e).__name__}: {e}")
                log.warning("bootstrap %s failed: %s", address, e)
        if bootstrapped:
            await self.lookup.run(self.identity.node_id)
        # Запись публикуется всегда: даже узел без bootstrap-контактов хранит
        # свою запись локально и разошлёт её при появлении соседей.
        await self.publish_self()
        report = JoinReport(
            bootstrapped=bootstrapped,
            failed=failed,
            contacts_after=len(self.table),
            duration_s=time.perf_counter() - started,
        )
        self.metrics.emit("node.join", **report.to_dict())
        return report

    async def lookup_node(self, target: bytes) -> LookupResult:
        """Найти узел по ``NodeID`` итеративным поиском DHT."""
        return await self.lookup.run(target)

    # ------------------------------------------------------- записи DHT

    def local_addresses(self) -> list[Address]:
        """Адреса, которые узел публикует в своей записи."""
        contact = self.peers.local_contact
        return [Address(host=contact.host, port=contact.port)]

    def build_self_record(self, *, sequence_number: int | None = None) -> NodeRecord:
        """Собрать и подписать актуальную запись о себе."""
        sequence = (
            sequence_number
            if sequence_number is not None
            else self.storage.sequence_for(self.node_id) + 1
        )
        return NodeRecord.create(
            self.identity,
            self.local_addresses(),
            sequence_number=sequence,
            ttl_seconds=self.config.record_ttl_seconds,
        )

    async def publish_self(self) -> PublishResult:
        """Опубликовать собственную адресную запись на R ближайших узлах."""
        record = self.build_self_record()
        return await self.put_record(record)

    async def put_record(self, record: NodeRecord) -> PublishResult:
        """Сохранить запись локально и разослать её R ближайшим к ключу узлам.

        Операция успешна, если подтверждений не меньше ``store_success_acks``
        (по умолчанию 2 из 3).
        """
        started = time.perf_counter()
        validate_record(record, self.config)
        key = record.record_key
        local = self.storage.put(record)
        if local.accepted:
            self.storage.save()

        found = await self.lookup.run(key)
        holders: list[str] = []
        acked = 1 if local.accepted else 0
        candidates = self._replication_candidates(key, found.contacts)
        results = await asyncio.gather(
            *(self._store_at(contact, key, record) for contact in candidates),
            return_exceptions=True,
        )
        for contact, result in zip(candidates, results, strict=True):
            if result is True:
                acked += 1
                holders.append(contact.node_id.hex())
            elif self.metrics is not None:
                self.metrics.emit(
                    "dht.store_failed",
                    peer=contact.short_id,
                    error=type(result).__name__ if isinstance(result, BaseException) else "refused",
                )

        success = acked >= self.config.store_success_acks
        if local.accepted:
            self._published_once = True
        report = PublishResult(
            record_key=key,
            sequence_number=record.sequence_number,
            local=local.accepted,
            acks=acked,
            holders=holders,
            success=success,
            duration_s=time.perf_counter() - started,
        )
        self.metrics.emit(
            "dht.publish",
            key=key.hex()[:12],
            node=self.node_id.hex()[:12],
            sequence_number=record.sequence_number,
            acks=acked,
            holders=len(holders),
            success=success,
            duration_s=round(report.duration_s, 6),
        )
        return report

    async def _store_at(self, contact: Contact, key: bytes, record: NodeRecord) -> bool:
        try:
            return await self.rpc.store(contact, key, record.to_cbor())
        except Exception:
            return False

    def _replication_candidates(self, key: bytes, found: list[Contact]) -> list[Contact]:
        """Выбрать до R ближайших к ключу узлов среди найденных и известных.

        Если поиск вернул меньше кандидатов, чем требуется для репликации
        (малая сеть или только что присоединившийся узел), набор дополняется
        ближайшими контактами таблицы маршрутизации.
        """
        limit = self.config.replication_factor
        chosen: list[Contact] = []
        seen: set[bytes] = {self.node_id}
        for contact in found:
            if contact.node_id in seen:
                continue
            chosen.append(contact)
            seen.add(contact.node_id)
            if len(chosen) >= limit:
                return chosen
        for contact in self.table.closest(key):
            if contact.node_id in seen:
                continue
            chosen.append(contact)
            seen.add(contact.node_id)
            if len(chosen) >= limit:
                break
        return chosen

    async def get_record(self, key: bytes) -> NodeRecord | None:
        """Найти запись по ключу: локально либо итеративным ``FIND_VALUE``."""
        local = self.storage.get(key)
        if local is not None:
            return local

        def _validate(payload: dict[str, Any]) -> None:
            candidate = parse_record(payload)
            validate_record(candidate, self.config)
            if candidate.record_key != key:
                raise RecordError("key does not match the record NodeID")

        result = await self.lookup.run(key, want_value=True, validator=_validate)
        if result.value is None:
            if self.metrics is not None:
                self.metrics.emit(
                    "dht.get_miss",
                    key=key.hex()[:12],
                    rpc=result.rpc_count,
                    rejected=result.rejected_values,
                )
            return None
        record = parse_record(result.value)
        # Найденную запись сохраняем: узел становится дополнительным хранителем.
        self.storage.put(record)
        if self.metrics is not None:
            self.metrics.emit(
                "dht.get_hit",
                key=key.hex()[:12],
                source=result.value_node.hex()[:12] if result.value_node else None,
                sequence_number=record.sequence_number,
            )
        return record

    async def resolve_contact(self, node_id: bytes) -> Contact:
        """Найти контакт узла по ``NodeID`` через подписанную запись DHT."""
        if node_id == self.node_id:
            return self.peers.local_contact
        known = self.table.get(node_id)
        record = await self.get_record(record_key_for_node(node_id))
        if record is None:
            if known is not None:
                return known
            raise RecordError(f"no address record for {node_id.hex()[:12]}")
        address = record.addresses[0]
        return Contact(
            node_id=record.node_id,
            public_key_der=record.identity_public_key,
            host=address.host,
            port=address.port,
        )

    # ------------------------------------------------------------- туннели

    async def build_tunnel(
        self, destination_node_id: bytes, constraints: dict[str, Any] | None = None
    ) -> Tunnel:
        """Построить туннель до узла по его подписанной адресной записи."""
        destination = await self.resolve_contact(destination_node_id)
        exclude: set[bytes] = set()
        if constraints:
            raw_exclude = constraints.get("exclude")
            if isinstance(raw_exclude, (list, tuple, set)):
                exclude = {item for item in raw_exclude if isinstance(item, bytes)}
        return await self.tunnels.build(destination, exclude=exclude)

    async def send_via_tunnel(self, tunnel_id: bytes, payload: bytes) -> int:
        """Отправить байты через активный туннель и дождаться подтверждения."""
        tunnel = self.tunnels.get(tunnel_id)
        if tunnel is None:
            raise TunnelError(f"unknown tunnel {tunnel_id.hex()[:12]}")
        seq = await self.tunnels.send_raw(tunnel, payload)
        await self.tunnels.wait_ack(
            tunnel, seq, self.config.tunnel_data_timeout_seconds
        )
        return seq

    async def close_tunnel(self, tunnel_id: bytes) -> None:
        """Закрыть туннель и освободить состояние ретрансляторов."""
        await self.tunnels.close(tunnel_id)

    async def send_message(self, destination_node_id: bytes, text: str) -> MessageRecord:
        """Отправить текстовое сообщение получателю через туннель."""
        return await self.messages.send_text(destination_node_id, text)

    # ------------------------------------------------------------ background

    async def _maintenance_loop(self) -> None:
        """Удаление записей по TTL и переопубликование собственной записи.

        Интервал переопубликования не превышает половины TTL
        (``republish_fraction <= 0.5``), поэтому запись не успевает истечь у
        хранителей между обновлениями.
        """
        interval = float(self.config.republish_interval_seconds)
        tick = max(0.2, min(interval / 2.0, 5.0))
        last = time.monotonic()
        self._published_once = False
        while not self._stopping:
            await asyncio.sleep(tick)
            if time.monotonic() - last < interval:
                continue
            last = time.monotonic()
            try:
                purged = self.storage.purge_expired()
                if purged:
                    self.metrics.emit("dht.records_expired", count=purged)
                if self._published_once and len(self.table) > 0:
                    report = await self.publish_self()
                    self.metrics.emit(
                        "dht.republish",
                        sequence_number=report.sequence_number,
                        acks=report.acks,
                        success=report.success,
                    )
                self.storage.save()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("record maintenance failed")

    async def _refresh_loop(self) -> None:
        """Периодическое обновление bucket: поиск случайной цели в их зоне."""
        interval = float(self.config.refresh_interval_seconds)
        last_refresh = time.monotonic()
        while not self._stopping:
            await asyncio.sleep(_REFRESH_TICK)
            if time.monotonic() - last_refresh < interval:
                continue
            last_refresh = time.monotonic()
            try:
                await self._refresh_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("refresh iteration failed")

    async def _refresh_once(self) -> None:
        """Один цикл refresh: собственная зона и по одной случайной цели."""
        await self.lookup.run(self.identity.node_id)
        stale = self.table.needs_refresh(
            self.config.refresh_interval_seconds, time.monotonic()
        )
        for index in stale[:3]:
            target = self._random_target_in_bucket(index)
            result = await self.lookup.run(target)
            self.metrics.emit(
                "dht.refresh",
                bucket=index,
                target=target.hex(),
                found=len(result.contacts),
                rpc=result.rpc_count,
            )

    def _random_target_in_bucket(self, index: int) -> bytes:
        """Случайный идентификатор, попадающий в зону bucket ``index``."""
        bits = self.config.node_id_bits
        value = self._rng.getrandbits(bits)
        if index < bits:
            # Совпадение старших битов и различие в бите (bits-1-index).
            shift = bits - index
            prefix = int.from_bytes(self.identity.node_id, "big") >> shift
            value = (prefix << shift) | (1 << (shift - 1)) | (value & ((1 << (shift - 1)) - 1))
        return value.to_bytes(self.config.node_id_bytes, "big")

    # --------------------------------------------------------------- snapshot

    def get_network_state(self) -> dict[str, Any]:
        """Состояние узла для CLI и экспериментов."""
        return {
            "node_id": self.node_id_hex,
            "address": self.address,
            "port": self.bound_port,
            "uptime_s": round(time.time() - self._started_at, 3) if self._started_at else 0.0,
            "config": {
                "n": self.config.node_id_bits,
                "k": self.config.k_bucket_size,
                "alpha": self.config.alpha,
                "replication_factor": self.config.replication_factor,
                "record_ttl_seconds": self.config.record_ttl_seconds,
            },
            "security": self.security.describe(),
            "routing": self.table.stats(),
            "buckets": self.table.bucket_table(),
            "contacts": [c.to_public_dict() for c in self.table.all_contacts()],
            "peers": self.peers.snapshot(),
            "rpc": self.rpc.stats(),
            "storage": self.storage.stats(),
            "records": self.storage.snapshot(),
            "tunnels": self.tunnels.snapshot(),
            "messages": self.messages.stats(),
            "dht_service": {
                "requests_in": self.service.requests_in,
                "requests_out": self.service.requests_out,
                "rejected": self.service.rejected,
            },
            "metrics": self.metrics.snapshot(),
        }
