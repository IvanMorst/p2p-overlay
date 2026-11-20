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

from .config import NodeConfig, PeerAddress
from .control import ControlServer
from .dht.contact import Contact
from .dht.lookup import IterativeLookup, LookupResult
from .dht.routing import AddResult, KBucket, RoutingTable
from .dht.rpc import DhtRpc
from .dht.service import DhtService
from .errors import HandshakeError
from .identity import Identity
from .metrics import EventRecorder
from .peers import PeerManager
from .security import SecurityLayer, build_security
from .transport.frame import Frame
from .transport.tcp import Connection, serve

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
        self.rpc = DhtRpc(self.peers, config, metrics=self.metrics)
        self.lookup = IterativeLookup(self.table, self.rpc, config, metrics=self.metrics)
        self.service = DhtService(self.identity, self.table, config, metrics=self.metrics)
        self._rng = random.Random(config.random_seed or None)
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
        """Запустить refresh и обслуживание записей DHT."""
        if self._background:
            return
        self._background.append(asyncio.create_task(self._refresh_loop(), name="dht-refresh"))

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
        await self.peers.close_all()
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

    # ------------------------------------------------------------ background

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
            "dht_service": {
                "requests_in": self.service.requests_in,
                "requests_out": self.service.requests_out,
                "rejected": self.service.rejected,
            },
            "metrics": self.metrics.snapshot(),
        }
