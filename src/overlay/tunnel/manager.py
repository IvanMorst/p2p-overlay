"""Управление туннелями: построение, состояние, передача, восстановление.

Туннель — зафиксированная последовательность различных узлов от инициатора к
получателю через промежуточные ретрансляторы. Инициатор и получатель не
считаются промежуточными узлами.

Построение идёт по цепочке: инициатор отправляет ``TUNNEL_BUILD`` первому
ретранслятору, тот проверяет маршрут и отправляет запрос следующему, и так до
получателя. Ответ ``TUNNEL_BUILD_OK`` возвращается тем же путём, поэтому
включение подтверждает каждый ретранслятор.

Данные передаются кадрами ``TUNNEL_DATA`` в обе стороны: ретранслятор
запоминает, с какого соединения пришёл запрос, и пересылает кадр на
противоположную сторону цепочки. Получатель подтверждает каждый кадр кадром
``TUNNEL_ACK``, который возвращается к инициатору.

Прикладное содержимое защищено end-to-end: внутри ``TUNNEL_DATA`` передаются
записи отдельной TLS 1.3-сессии «инициатор — получатель» (см. ``tunnel.e2e``).
Ретранслятор видит только служебные поля и ciphertext.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from ..dht.contact import Contact
from ..errors import HandshakeError, RemoteError, TimeoutExpired, TunnelError
from ..transport import codec
from ..transport.frame import FLAG_ERROR, FLAG_RESPONSE, Frame, MsgType
from ..transport.tcp import Connection
from .e2e import E2EChannel, E2ESession
from .route import Route, RouteHop, validate_route

if TYPE_CHECKING:  # pragma: no cover - только для аннотаций
    from ..node import Node

log = logging.getLogger(__name__)

TUNNEL_MESSAGES = frozenset(
    {
        MsgType.TUNNEL_BUILD,
        MsgType.TUNNEL_BUILD_OK,
        MsgType.TUNNEL_BUILD_FAIL,
        MsgType.TUNNEL_DATA,
        MsgType.TUNNEL_ACK,
        MsgType.TUNNEL_CLOSE,
    }
)


class TunnelState(StrEnum):
    BUILDING = "BUILDING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    CLOSING = "CLOSING"
    DEAD = "DEAD"


@dataclass(slots=True)
class TunnelEvent:
    at: float
    state: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"at": round(self.at, 6), "state": self.state, "reason": self.reason}


@dataclass(slots=True)
class Tunnel:
    """Туннель на стороне инициатора."""

    tunnel_id: bytes
    destination: Contact
    relays: list[Contact]
    entry_conn: Connection
    state: TunnelState = TunnelState.BUILDING
    created_at: float = field(default_factory=time.time)
    last_ack_at: float = field(default_factory=time.time)
    last_ack_seq: int = 0
    seq: int = 0
    attempts: int = 1
    e2e: E2ESession | None = None
    events: list[TunnelEvent] = field(default_factory=list)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    pending: dict[int, asyncio.Future[None]] = field(default_factory=dict)

    @property
    def short_id(self) -> str:
        return self.tunnel_id[:6].hex()

    def path_ids(self) -> list[bytes]:
        return [self.destination.node_id]

    def hops(self, local_id: bytes) -> list[str]:        return [local_id[:6].hex()] + [r.short_id for r in self.relays] + [self.destination.short_id]

    def transition(self, state: TunnelState, reason: str = "") -> None:
        self.state = state
        self.events.append(TunnelEvent(time.time(), state.value, reason))
        log.debug("tunnel %s -> %s (%s)", self.short_id, state.value, reason)

    def to_dict(self, local_id: bytes) -> dict[str, Any]:
        return {
            "tunnel_id": self.tunnel_id.hex(),
            "state": self.state.value,
            "hops": self.hops(local_id),
            "relays": len(self.relays),
            "destination": self.destination.node_id.hex(),
            "created_at": round(self.created_at, 6),
            "age_s": round(time.time() - self.created_at, 3),
            "last_ack_age_s": round(time.time() - self.last_ack_at, 3),
            "attempts": self.attempts,
            "e2e": {
                "ready": bool(self.e2e and self.e2e.ready),
                "tls": self.e2e.tls_version if self.e2e else None,
                "peer": self.e2e.peer.short_id if self.e2e and self.e2e.peer else None,
            },
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(slots=True)
class RelayTunnel:
    """Туннель на стороне ретранслятора или получателя."""

    tunnel_id: bytes
    prev: Connection
    prev_node: bytes
    next: Connection | None = None
    next_node: bytes | None = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    forwarded: int = 0
    endpoint: bool = False
    e2e: E2ESession | None = None
    reader: asyncio.Task[None] | None = None
    out_seq: int = 0

    @property
    def short_id(self) -> str:
        return self.tunnel_id[:6].hex()


class TunnelManager:
    """Подсистема Tunnel Management узла."""

    def __init__(self, node: Node) -> None:
        self.node = node
        self.config = node.config
        self.identity = node.identity
        self.peers = node.peers
        self.metrics = node.metrics
        self._tunnels: dict[bytes, Tunnel] = {}
        self._relays: dict[bytes, RelayTunnel] = {}
        self._by_destination: dict[bytes, bytes] = {}
        self._health_task: asyncio.Task[None] | None = None
        self._stopping = False
        self.on_app_message: Any = None
        self.rebuilds = 0
        self.frames_forwarded = 0
        self.frames_dropped = 0
        self._last_attempt_relays: list[Contact] = []

    # ------------------------------------------------------------- жизненный

    def start(self) -> None:
        if self._health_task is None:
            self._health_task = asyncio.create_task(self._health_loop(), name="tunnel-health")

    async def stop(self) -> None:
        self._stopping = True
        if self._health_task is not None:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._health_task
            self._health_task = None
        for tunnel in list(self._tunnels.values()):
            with contextlib.suppress(Exception):
                await self.close(tunnel.tunnel_id)
        self._tunnels.clear()
        self._by_destination.clear()
        for relay in list(self._relays.values()):
            self._drop_relay(relay.tunnel_id)
        self._relays.clear()

    # ------------------------------------------------------------ построение

    def _select_relays(self, destination: Contact, exclude: set[bytes]) -> list[Contact]:
        need = self.config.tunnel_min_relays
        forbidden = {self.identity.node_id, destination.node_id} | exclude
        candidates = [
            contact
            for contact in self.node.table.all_contacts()
            if contact.node_id not in forbidden and contact.node_id != destination.node_id
        ]
        if len(candidates) < need:
            raise TunnelError(
                f"not enough relays: {len(candidates)} available, {need} required"
            )
        chosen = self.node._rng.sample(candidates, need)
        return chosen

    async def build(
        self,
        destination: Contact,
        *,
        exclude: set[bytes] | None = None,
        attempts: int | None = None,
    ) -> Tunnel:
        """Построить туннель до получателя, подтверждённый каждым ретранслятором."""
        limit = attempts or self.config.tunnel_max_retries
        blocked = set(exclude or ())
        last_error: Exception | None = None
        for attempt in range(1, limit + 1):
            try:
                tunnel = await self._build_once(destination, blocked, attempt)
                self._tunnels[tunnel.tunnel_id] = tunnel
                self._by_destination[destination.node_id] = tunnel.tunnel_id
                self.metrics.emit(
                    "tunnel.active",
                    tunnel_id=tunnel.tunnel_id.hex(),
                    hops=tunnel.hops(self.identity.node_id),
                    relays=len(tunnel.relays),
                    attempt=attempt,
                )
                return tunnel
            except TunnelError as e:
                last_error = e
                # Следующая попытка не должна повторять уже отказавший набор.
                blocked.update(contact.node_id for contact in self._last_attempt_relays)
                self.metrics.emit(
                    "tunnel.build_failed", attempt=attempt, error=str(e),
                    destination=destination.short_id,
                )
        raise TunnelError(f"cannot build tunnel to {destination.short_id}: {last_error}")

    async def _build_once(
        self, destination: Contact, blocked: set[bytes], attempt: int
    ) -> Tunnel:
        client_context = self.node.security.client_context()
        if client_context is None:
            raise TunnelError("tunnels require a protected channel (security.mode = tls13)")
        relays = self._select_relays(destination, blocked)
        self._last_attempt_relays = list(relays)
        route = Route(tuple(RouteHop.from_contact(c) for c in [*relays, destination]))
        validate_route(
            route,
            local_id=self.identity.node_id,
            max_hops=self.config.tunnel_max_hops,
            min_relays=self.config.tunnel_min_relays,
            initiator_id=self.identity.node_id,
        )
        tunnel_id = secrets.token_bytes(16)
        first = relays[0]
        try:
            entry = await self.peers.dial(first)
        except (HandshakeError, TimeoutExpired, ConnectionError, OSError) as e:
            raise TunnelError(f"cannot reach relay {first.short_id}: {e}") from e
        tunnel = Tunnel(
            tunnel_id=tunnel_id,
            destination=destination,
            relays=relays,
            entry_conn=entry,
            attempts=attempt,
        )
        # Туннель регистрируется до e2e-рукопожатия: ответные кадры получателя
        # приходят как TUNNEL_DATA и должны найти свой туннель.
        self._tunnels[tunnel_id] = tunnel
        tunnel.transition(TunnelState.BUILDING, "build request sent")

        payload = codec.encode_payload(
            {
                "tunnel_id": tunnel_id,
                "route": route.to_cbor(),
                "index": 0,
                "ttl": int(self.config.tunnel_ttl_seconds),
                "max_hops": self.config.tunnel_max_hops,
            }
        )
        try:
            reply = await entry.request(
                MsgType.TUNNEL_BUILD,
                payload=payload,
                timeout=self.config.tunnel_build_timeout_seconds,
                expected_type=MsgType.TUNNEL_BUILD_OK,
            )
        except (TimeoutExpired, RemoteError, ConnectionError, OSError) as e:
            tunnel.transition(TunnelState.DEAD, f"build failed: {e}")
            self._tunnels.pop(tunnel_id, None)
            raise TunnelError(f"relay {first.short_id} failed: {e}") from e

        obj = codec.decode_mapping(reply.payload)
        if obj.get("tunnel_id") != tunnel_id:
            tunnel.transition(TunnelState.DEAD, "tunnel_id mismatch in build reply")
            self._tunnels.pop(tunnel_id, None)
            raise TunnelError("build reply carries a foreign tunnel_id")

        session = E2ESession(
            E2EChannel(client_context, server_side=False),
            lambda data: self._send_ciphertext(tunnel, data),
            node_id_bits=self.config.node_id_bits,
            expected_peer=destination.node_id,
        )
        tunnel.e2e = session
        try:
            await session.start(self.config.tunnel_build_timeout_seconds)
        except Exception as e:
            tunnel.transition(TunnelState.DEAD, f"e2e handshake failed: {e!r}")
            self._tunnels.pop(tunnel_id, None)
            raise TunnelError(f"e2e handshake failed: {e!r}") from e

        tunnel.transition(TunnelState.ACTIVE, "all hops confirmed")
        return tunnel

    # --------------------------------------------------------------- передача

    async def _send_ciphertext(self, tunnel: Tunnel, data: bytes) -> None:
        tunnel.seq += 1
        seq = tunnel.seq
        payload = codec.encode_payload(
            {"tunnel_id": tunnel.tunnel_id, "seq": seq, "payload": data}
        )
        try:
            await tunnel.entry_conn.send(
                Frame(
                    type=MsgType.TUNNEL_DATA,
                    request_id=Frame.new_request_id(),
                    payload=payload,
                )
            )
        except (ConnectionError, OSError) as e:
            log.debug("send failed for tunnel %s: %r", tunnel.short_id, e)
            tunnel.transition(TunnelState.DEGRADED, "entry connection lost")
            raise TunnelError(f"tunnel {tunnel.short_id} is broken: {e}") from e

    async def send_raw(self, tunnel: Tunnel, data: bytes) -> int:
        """Отправить байты через туннель и вернуть номер кадра."""
        await self._send_ciphertext(tunnel, data)
        return tunnel.seq

    async def wait_ack(self, tunnel: Tunnel, seq: int, timeout: float) -> None:
        """Дождаться подтверждения кадра получателем."""
        if tunnel.last_ack_seq >= seq:
            return
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        tunnel.pending[seq] = future
        try:
            await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as e:
            raise TimeoutExpired(f"no tunnel ack for frame {seq}") from e
        finally:
            tunnel.pending.pop(seq, None)

    async def request(
        self, tunnel: Tunnel, message: dict[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        """Отправить прикладное сообщение и дождаться ответа по тому же туннелю."""
        if tunnel.e2e is None or not tunnel.e2e.ready:
            raise TunnelError("tunnel e2e session is not ready")
        if tunnel.state is not TunnelState.ACTIVE:
            raise TunnelError(f"tunnel state is {tunnel.state.value}")
        limit = timeout or self.config.tunnel_data_timeout_seconds
        async with tunnel.send_lock:
            await tunnel.e2e.send(message)
            return await tunnel.e2e.receive(limit)

    async def ensure_tunnel(self, destination: Contact) -> Tunnel:
        """Вернуть активный туннель к получателю, при необходимости перестроить."""
        existing_id = self._by_destination.get(destination.node_id)
        if existing_id is not None:
            tunnel = self._tunnels.get(existing_id)
            if tunnel is not None and tunnel.state is TunnelState.ACTIVE:
                return tunnel
            failed = tunnel
            self._tunnels.pop(existing_id, None)
            if failed is not None:
                self.rebuilds += 1
                self.metrics.emit(
                    "tunnel.degraded",
                    tunnel_id=failed.tunnel_id.hex(),
                    reason=failed.state.value,
                )
                await self.close(failed.tunnel_id, notify=False)
        return await self.build(destination)

    async def send_message(
        self,
        destination: Contact,
        message: dict[str, Any],
        *,
        timeout: float | None = None,
    ) -> tuple[Tunnel, dict[str, Any]]:
        """Отправить сообщение, автоматически перестроив туннель при отказе."""
        last_error: Exception | None = None
        for attempt in range(1, self.config.tunnel_max_retries + 1):
            tunnel = await self.ensure_tunnel(destination)
            try:
                reply = await self.request(tunnel, message, timeout=timeout)
                return tunnel, reply
            except (TimeoutExpired, TunnelError, ConnectionError, OSError) as e:
                last_error = e
                tunnel.transition(TunnelState.DEGRADED, f"delivery failed: {e}")
                self.metrics.emit(
                    "tunnel.degraded",
                    tunnel_id=tunnel.tunnel_id.hex(),
                    reason=str(e),
                    attempt=attempt,
                )
                self._by_destination.pop(destination.node_id, None)
                # Сначала исключаем последний ретранслятор: именно он отвечает
                # за доставку до получателя. Если отказ был раньше, следующая
                # попытка внутри build() заблокирует и остальных участников.
                failed_relays = {tunnel.relays[-1].node_id} if tunnel.relays else set()
                await self.close(tunnel.tunnel_id, notify=False)
                self.rebuilds += 1
                self.metrics.emit(
                    "tunnel.rebuild_attempt",
                    old_tunnel=tunnel.tunnel_id.hex(),
                    excluded=[relay.hex()[:12] for relay in failed_relays],
                )
                try:
                    replacement = await self.build(destination, exclude=failed_relays)
                except TunnelError as rebuild_error:
                    last_error = rebuild_error
                    continue
                self.metrics.emit(
                    "tunnel.rebuilt",
                    old_tunnel=tunnel.tunnel_id.hex(),
                    new_tunnel=replacement.tunnel_id.hex(),
                    hops=replacement.hops(self.identity.node_id),
                )
        raise TunnelError(f"delivery failed after retries: {last_error}")

    async def close(self, tunnel_id: bytes, *, notify: bool = True) -> None:
        tunnel = self._tunnels.pop(tunnel_id, None)
        if tunnel is None:
            return
        tunnel.transition(TunnelState.CLOSING, "close requested")
        if notify and not tunnel.entry_conn.closed:
            with contextlib.suppress(Exception):
                await tunnel.entry_conn.send(
                    Frame(
                        type=MsgType.TUNNEL_CLOSE,
                        request_id=Frame.new_request_id(),
                        payload=codec.encode_payload({"tunnel_id": tunnel_id}),
                    )
                )
        tunnel.transition(TunnelState.DEAD, "closed")
        if self._by_destination.get(tunnel.destination.node_id) == tunnel_id:
            self._by_destination.pop(tunnel.destination.node_id, None)

    # -------------------------------------------------------- обработка кадров

    async def handle(self, conn: Connection, peer: Contact | None, frame: Frame) -> bool:
        if frame.type not in TUNNEL_MESSAGES:
            return False
        try:
            if frame.type == MsgType.TUNNEL_BUILD:
                await self._on_build(conn, peer, frame)
            elif frame.type == MsgType.TUNNEL_DATA:
                await self._on_data(conn, frame)
            elif frame.type == MsgType.TUNNEL_ACK:
                await self._on_ack(conn, frame)
            elif frame.type == MsgType.TUNNEL_CLOSE:
                await self._on_close(conn, frame)
            else:
                # TUNNEL_BUILD_OK / FAIL как входящие запросы не ожидаются.
                await self._reply_error(conn, frame, "unexpected tunnel message")
        except TunnelError as e:
            log.warning("tunnel frame 0x%02x rejected: %s", frame.type, e)
            self.frames_dropped += 1
        except (ConnectionError, OSError) as e:
            # Обрыв на следующем переходе: кадр теряется, туннель деградирует
            # по тайм-ауту подтверждения.
            log.warning("tunnel frame 0x%02x forwarding failed: %s", frame.type, e)
            self.frames_dropped += 1
        return True

    async def _on_build(self, conn: Connection, peer: Contact | None, frame: Frame) -> None:
        obj = codec.decode_mapping(frame.payload)
        tunnel_id = obj.get("tunnel_id")
        if not isinstance(tunnel_id, bytes) or len(tunnel_id) != 16:
            await self._reply_fail(conn, frame, tunnel_id, "invalid tunnel_id")
            return
        if tunnel_id in self._relays or tunnel_id in self._tunnels:
            await self._reply_fail(conn, frame, tunnel_id, "duplicate tunnel_id")
            return
        try:
            route = Route.from_cbor(obj.get("route"))
            index = int(obj.get("index", -1))
            max_hops = int(obj.get("max_hops", self.config.tunnel_max_hops))
            ttl = int(obj.get("ttl", 0))
        except (TunnelError, TypeError, ValueError) as e:
            await self._reply_fail(conn, frame, tunnel_id, f"malformed build: {e}")
            return

        if index < 0 or index >= len(route.hops):
            await self._reply_fail(conn, frame, tunnel_id, "index out of range")
            return
        if route.hops[index].node_id != self.identity.node_id:
            await self._reply_fail(conn, frame, tunnel_id, "route is not addressed to this node")
            return
        try:
            validate_route(
                route,
                local_id=self.identity.node_id,
                max_hops=max_hops,
                min_relays=self.config.tunnel_min_relays,
            )
        except TunnelError as e:
            await self._reply_fail(conn, frame, tunnel_id, str(e))
            return
        if ttl <= 0:
            await self._reply_fail(conn, frame, tunnel_id, "tunnel TTL is exhausted")
            return

        if index == len(route.hops) - 1:
            # Я получатель: дальше передачи нет.
            relay = RelayTunnel(
                tunnel_id=tunnel_id,
                prev=conn,
                prev_node=route.hops[index - 1].node_id,
                endpoint=True,
            )
            self._relays[tunnel_id] = relay
            await self._reply_ok(conn, frame, tunnel_id, index)
            self.metrics.emit(
                "tunnel.endpoint",
                tunnel_id=tunnel_id.hex(),
                hops=len(route.hops),
                source=relay.prev_node.hex()[:12],
            )
            return

        next_hop = route.hops[index + 1]
        try:
            next_conn = await self.peers.dial(next_hop.to_contact())
            reply = await next_conn.request(
                MsgType.TUNNEL_BUILD,
                payload=codec.encode_payload(
                    {
                        "tunnel_id": tunnel_id,
                        "route": route.to_cbor(),
                        "index": index + 1,
                        "ttl": ttl - 1,
                        "max_hops": max_hops,
                    }
                ),
                timeout=self.config.tunnel_build_timeout_seconds,
                expected_type=MsgType.TUNNEL_BUILD_OK,
            )
        except (TimeoutExpired, RemoteError, ConnectionError, OSError) as e:
            await self._reply_fail(conn, frame, tunnel_id, f"next hop failed: {e}")
            return

        relay = RelayTunnel(
            tunnel_id=tunnel_id,
            prev=conn,
            prev_node=(
                route.hops[index - 1].node_id
                if index >= 1
                else (peer.node_id if peer is not None else b"")
            ),
            next=next_conn,
            next_node=next_hop.node_id,
        )
        self._relays[tunnel_id] = relay
        self.metrics.emit(
            "tunnel.relay",
            tunnel_id=tunnel_id.hex(),
            index=index,
            next=next_hop.short_id,
        )
        await conn.send(
            Frame(
                type=MsgType.TUNNEL_BUILD_OK,
                request_id=frame.request_id,
                payload=reply.payload,
                flags=FLAG_RESPONSE,
            )
        )

    async def _on_data(self, conn: Connection, frame: Frame) -> None:
        obj = codec.decode_mapping(frame.payload)
        tunnel_id = obj.get("tunnel_id")
        if not isinstance(tunnel_id, bytes):
            raise TunnelError("TUNNEL_DATA without tunnel_id")
        payload = obj.get("payload")
        if not isinstance(payload, bytes):
            raise TunnelError("TUNNEL_DATA without payload")
        seq = obj.get("seq")
        if not isinstance(seq, int):
            raise TunnelError("TUNNEL_DATA without seq")

        log.debug(
            "tunnel data tunnel=%s seq=%d bytes=%d",
            tunnel_id.hex()[:8],
            seq,
            len(payload),
        )
        relay = self._relays.get(tunnel_id)
        if relay is not None:
            relay.last_seen = time.time()
            if relay.endpoint:
                await self._deliver_endpoint(relay, payload)
                await self._send_relay_frame(relay, MsgType.TUNNEL_ACK, {"seq": seq})
                return
            target = relay.next if conn is relay.prev else relay.prev
            if target is None:
                raise TunnelError("relay has no forwarding target")
            relay.forwarded += 1
            self.frames_forwarded += 1
            await target.send(
                Frame(
                    type=MsgType.TUNNEL_DATA,
                    request_id=Frame.new_request_id(),
                    payload=frame.payload,
                )
            )
            return

        if tunnel_id in self._tunnels:
            tunnel = self._tunnels[tunnel_id]
            if tunnel.e2e is None:
                raise TunnelError("initiator tunnel has no e2e session")
            await tunnel.e2e.feed(payload)
            return
        raise TunnelError(f"unknown tunnel {tunnel_id.hex()[:12]}")

    async def _on_ack(self, conn: Connection, frame: Frame) -> None:
        obj = codec.decode_mapping(frame.payload)
        tunnel_id = obj.get("tunnel_id")
        if not isinstance(tunnel_id, bytes):
            raise TunnelError("TUNNEL_ACK without tunnel_id")
        relay = self._relays.get(tunnel_id)
        if relay is not None and not relay.endpoint:
            target = relay.next if conn is relay.prev else relay.prev
            if target is not None:
                await target.send(
                    Frame(
                        type=MsgType.TUNNEL_ACK,
                        request_id=Frame.new_request_id(),
                        payload=frame.payload,
                    )
                )
            return
        tunnel = self._tunnels.get(tunnel_id)
        if tunnel is not None:
            tunnel.last_ack_at = time.time()
            seq = obj.get("seq")
            if isinstance(seq, int):
                tunnel.last_ack_seq = max(tunnel.last_ack_seq, seq)
                future = tunnel.pending.pop(seq, None)
                if future is not None and not future.done():
                    future.set_result(None)
            return

    async def _on_close(self, conn: Connection, frame: Frame) -> None:
        obj = codec.decode_mapping(frame.payload)
        tunnel_id = obj.get("tunnel_id")
        if not isinstance(tunnel_id, bytes):
            raise TunnelError("TUNNEL_CLOSE without tunnel_id")
        relay = self._relays.get(tunnel_id)
        if relay is not None:
            target = relay.next if conn is relay.prev else relay.prev
            if target is not None and not relay.endpoint:
                with contextlib.suppress(Exception):
                    await target.send(
                        Frame(
                            type=MsgType.TUNNEL_CLOSE,
                            request_id=Frame.new_request_id(),
                            payload=frame.payload,
                        )
                    )
            self._drop_relay(tunnel_id)
            return
        tunnel = self._tunnels.get(tunnel_id)
        if tunnel is not None:
            tunnel.transition(TunnelState.DEAD, "closed by peer")
            self._tunnels.pop(tunnel_id, None)
            self._by_destination.pop(tunnel.destination.node_id, None)

    # -------------------------------------------------------- сторона endpoint

    async def _deliver_endpoint(self, relay: RelayTunnel, payload: bytes) -> None:
        if relay.e2e is None:
            relay.e2e = self._create_endpoint_session(relay)
        await relay.e2e.feed(payload)

    def _create_endpoint_session(self, relay: RelayTunnel) -> E2ESession:
        context = self.node.security.server_context()
        if context is None:
            raise TunnelError("secure channel is required for tunnels")
        channel = E2EChannel(context, server_side=True)
        session = E2ESession(
            channel,
            lambda data: self._send_relay_ciphertext(relay, data),
            node_id_bits=self.config.node_id_bits,
        )
        relay.reader = asyncio.create_task(
            self._endpoint_reader(relay, session), name="tunnel-e2e-reader"
        )
        return session

    async def _send_relay_ciphertext(self, relay: RelayTunnel, data: bytes) -> None:
        relay.out_seq += 1
        payload = codec.encode_payload(
            {"tunnel_id": relay.tunnel_id, "seq": relay.out_seq, "payload": data}
        )
        await relay.prev.send(
            Frame(
                type=MsgType.TUNNEL_DATA,
                request_id=Frame.new_request_id(),
                payload=payload,
            )
        )

    async def _send_relay_frame(
        self, relay: RelayTunnel, msg_type: int, obj: dict[str, Any]
    ) -> None:
        payload = {"tunnel_id": relay.tunnel_id, **obj}
        try:
            await relay.prev.send(
                Frame(
                    type=msg_type,
                    request_id=Frame.new_request_id(),
                    payload=codec.encode_payload(payload),
                )
            )
        except (ConnectionError, OSError):
            self._drop_relay(relay.tunnel_id)

    async def _endpoint_reader(self, relay: RelayTunnel, session: E2ESession) -> None:
        try:
            await session.wait_ready(self.config.tunnel_build_timeout_seconds)
        except (TimeoutError, TunnelError, asyncio.CancelledError):
            return
        peer_id = session.peer.node_id if session.peer else None
        while not self._stopping:
            try:
                message = await session.receive(self.config.tunnel_ttl_seconds)
            except (TimeoutError, TunnelError, asyncio.CancelledError):
                break
            if self.on_app_message is None:
                continue
            try:
                await self.on_app_message(message, session, peer_id)
            except Exception:
                log.exception("app message handler failed")

    # ---------------------------------------------------------------- health

    async def _health_loop(self) -> None:
        interval = max(0.2, self.config.tunnel_health_interval_seconds)
        while not self._stopping:
            await asyncio.sleep(interval)
            now = time.time()
            probes = []
            for tunnel in list(self._tunnels.values()):
                if tunnel.state is not TunnelState.ACTIVE:
                    continue
                if now - tunnel.last_ack_at <= interval * 2:
                    continue
                probes.append(asyncio.create_task(self._probe(tunnel), name="tunnel-probe"))
            if probes:
                await asyncio.gather(*probes, return_exceptions=True)
            for relay in list(self._relays.values()):
                if relay.prev.closed or (relay.next is not None and relay.next.closed):
                    self.frames_dropped += 1
                    self._drop_relay(relay.tunnel_id)

    async def _probe(self, tunnel: Tunnel) -> None:
        """Проверить туннель пустым кадром; без подтверждения — деградация."""
        try:
            seq = await self.send_raw(tunnel, b"")
            await self.wait_ack(tunnel, seq, self.config.tunnel_data_timeout_seconds)
        except (TimeoutExpired, TunnelError, ConnectionError, OSError) as e:
            tunnel.transition(TunnelState.DEGRADED, f"health probe failed: {e}")
            self.metrics.emit(
                "tunnel.degraded", tunnel_id=tunnel.tunnel_id.hex(), reason=str(e)
            )

    def _drop_relay(self, tunnel_id: bytes) -> None:
        relay = self._relays.pop(tunnel_id, None)
        if relay is None:
            return
        if relay.reader is not None:
            relay.reader.cancel()

    # -------------------------------------------------------------- служебное

    async def _reply_ok(
        self, conn: Connection, request: Frame, tunnel_id: bytes, index: int
    ) -> None:
        await conn.send(
            Frame(
                type=MsgType.TUNNEL_BUILD_OK,
                request_id=request.request_id,
                payload=codec.encode_payload(
                    {"tunnel_id": tunnel_id, "index": index, "node_id": self.identity.node_id}
                ),
                flags=FLAG_RESPONSE,
            )
        )

    async def _reply_fail(
        self, conn: Connection, request: Frame, tunnel_id: Any, reason: str
    ) -> None:
        payload = {
            "tunnel_id": tunnel_id if isinstance(tunnel_id, bytes) else b"",
            "code": 0x0C,
            "detail": reason,
        }
        with contextlib.suppress(Exception):
            await conn.send(
                Frame(
                    type=MsgType.TUNNEL_BUILD_FAIL,
                    request_id=request.request_id,
                    payload=codec.encode_payload(payload),
                    flags=FLAG_ERROR,
                )
            )

    async def _reply_error(self, conn: Connection, request: Frame, detail: str) -> None:
        with contextlib.suppress(Exception):
            await conn.send(
                Frame(
                    type=MsgType.ERROR,
                    request_id=request.request_id,
                    payload=codec.encode_payload({"code": 0x0C, "detail": detail}),
                    flags=FLAG_ERROR,
                )
            )

    def get(self, tunnel_id: bytes) -> Tunnel | None:
        return self._tunnels.get(tunnel_id)

    def active_tunnels(self) -> list[Tunnel]:
        return [t for t in self._tunnels.values() if t.state is TunnelState.ACTIVE]

    def snapshot(self) -> dict[str, Any]:
        return {
            "tunnels": [t.to_dict(self.identity.node_id) for t in self._tunnels.values()],
            "relays": [
                {
                    "tunnel_id": r.tunnel_id.hex(),
                    "endpoint": r.endpoint,
                    "forwarded": r.forwarded,
                    "prev": r.prev_node.hex()[:12],
                    "next": r.next_node.hex()[:12] if r.next_node else None,
                }
                for r in self._relays.values()
            ],
            "active": len(self.active_tunnels()),
            "rebuilds": self.rebuilds,
            "forwarded": self.frames_forwarded,
            "dropped": self.frames_dropped,
        }


