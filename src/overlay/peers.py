"""Управление соединениями между узлами: HELLO-рукопожатие и кэш соединений.

Каждое новое соединение начинается обменом ``HELLO`` / ``HELLO_OK``:

1. инициатор отправляет ``HELLO`` со своим ``NodeID``, открытым ключом и
   объявленным адресом;
2. принимающая сторона проверяет, что ``NodeID = SHA-256(public_key)`` и что
   ключ совпадает с ключом из TLS-сертификата (если канал защищён);
3. при несовпадении отправляется ``ERROR`` с кодом ``IDENTITY_MISMATCH`` и
   соединение закрывается без выполнения прикладных действий.

Приёмник считает идентичность подтверждённой только после шага 2, поэтому
прикладной слой никогда не видит «неаутентифицированного» собеседника.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .addressing import is_valid_host, is_valid_port
from .config import NodeConfig
from .dht.contact import Contact
from .errors import HandshakeError, IdentityError, ProtocolError, RemoteError, TimeoutExpired
from .identity import Identity, verify_node_id
from .metrics import EventRecorder
from .security.base import SecurityError, SecurityLayer
from .transport import codec, connect
from .transport.frame import FLAG_ERROR, FLAG_RESPONSE, ErrorCode, Frame, MsgType
from .transport.tcp import Connection

log = logging.getLogger(__name__)

HELLO_VERSION = 1
_UNSPECIFIED_HOSTS = {"", "0.0.0.0", "::", "[::]"}


FrameHandler = Callable[[Frame], Awaitable[None]]


class PeerManager:
    """Аутентификация собеседника и кэш исходящих соединений."""

    def __init__(
        self,
        identity: Identity,
        config: NodeConfig,
        security: SecurityLayer,
        *,
        metrics: EventRecorder | None = None,
    ) -> None:
        self._identity = identity
        self._config = config
        self._security = security
        self._metrics = metrics
        self._connections: dict[bytes, Connection] = {}
        self._locks: dict[bytes, asyncio.Lock] = {}
        self._bound_port = 0
        self._dispatcher: Callable[[Connection, Contact, Frame], Awaitable[None]] | None = None
        self._advertise_host = config.advertise_host or (
            "127.0.0.1" if config.listen_host in _UNSPECIFIED_HOSTS else config.listen_host
        )

    def set_dispatcher(
        self,
        dispatcher: Callable[[Connection, Contact, Frame], Awaitable[None]],
    ) -> None:
        """Назначить обработчик неожиданных (не ответных) кадров соединения.

        Он нужен для входящих кадров туннеля: ``TUNNEL_DATA`` и ``TUNNEL_ACK``
        приходят на исходящее соединение узла и не являются ответом на запрос.
        """
        self._dispatcher = dispatcher

    def _attach_dispatcher(self, conn: Connection, contact: Contact) -> None:
        if self._dispatcher is None:
            return
        dispatcher = self._dispatcher

        async def handler(frame: Frame) -> None:
            await dispatcher(conn, contact, frame)

        conn.set_handler(handler)

    # ------------------------------------------------------------- accessors

    @property
    def identity(self) -> Identity:
        return self._identity

    @property
    def security(self) -> SecurityLayer:
        return self._security

    @property
    def local_contact(self) -> Contact:
        return Contact(
            node_id=self._identity.node_id,
            public_key_der=self._identity.public_key_der,
            host=self._advertise_host,
            port=self.bound_port,
        )

    def hello_payload(self) -> dict[str, Any]:
        return {
            "version": HELLO_VERSION,
            "node_id": self._identity.node_id,
            "key": self._identity.public_key_der,
            "host": self._advertise_host,
            "port": self.bound_port,
        }

    def set_bound_port(self, port: int) -> None:
        """Зафиксировать фактический порт прослушивания (актуально для port=0)."""
        self._bound_port = port

    @property
    def bound_port(self) -> int:
        return getattr(self, "_bound_port", 0) or self._config.listen_port

    def cache(self, node_id: bytes, conn: Connection) -> None:
        """Положить соединение в кэш повторного использования."""
        self._connections[node_id] = conn

    def cached_connection(self, node_id: bytes) -> Connection | None:
        conn = self._connections.get(node_id)
        if conn is None or conn.closed:
            self._connections.pop(node_id, None)
            return None
        return conn

    @property
    def open_connections(self) -> int:
        return sum(1 for c in self._connections.values() if not c.closed)

    # -------------------------------------------------------------- handshake

    async def accept(self, conn: Connection, handler: FrameHandler) -> Contact:
        """Принять входящее соединение: дождаться и проверить ``HELLO``."""
        loop = asyncio.get_running_loop()
        hello: asyncio.Future[Frame] = loop.create_future()

        async def _wait_hello(frame: Frame) -> None:
            if frame.type != MsgType.HELLO:
                return
            if not hello.done():
                hello.set_result(frame)

        conn.set_handler(_wait_hello)
        try:
            frame = await asyncio.wait_for(hello, timeout=self._config.handshake_timeout_seconds)
        except TimeoutError as e:
            raise HandshakeError("peer did not send HELLO") from e

        try:
            contact = self._validate_hello(frame, conn, expected=None)
        except (HandshakeError, ProtocolError, IdentityError) as e:
            await self._reject(conn, str(e))
            raise HandshakeError(str(e)) from e

        reply = Frame(
            type=MsgType.HELLO_OK,
            request_id=frame.request_id,
            payload=codec.encode_payload(self.hello_payload()),
            flags=FLAG_RESPONSE,
        )
        await conn.send(reply)
        conn.set_handler(handler)
        if self._metrics is not None:
            self._metrics.emit(
                "peer.accept", peer=contact.short_id, address=contact.address,
                tls=conn.tls_version,
            )
        return contact

    async def dial(
        self,
        contact: Contact,
        *,
        expected_node_id: bytes | None = None,
    ) -> Connection:
        """Установить (или взять из кэша) соединение с контактом."""
        if expected_node_id is not None and expected_node_id != contact.node_id:
            raise HandshakeError(
                "contact NodeID does not match the expected identity: "
                f"{contact.node_id.hex()[:12]} != {expected_node_id.hex()[:12]}"
            )
        cached = self.cached_connection(contact.node_id)
        if cached is not None:
            return cached

        lock = self._locks.setdefault(contact.node_id, asyncio.Lock())
        async with lock:
            cached = self.cached_connection(contact.node_id)
            if cached is not None:
                return cached
            conn = await self._open(contact, expected_node_id or contact.node_id)
            self._connections[contact.node_id] = conn
            return conn

    async def dial_address(
        self,
        host: str,
        port: int,
        *,
        expected_node_id: bytes | None = None,
    ) -> tuple[Connection, Contact]:
        """Подключиться по адресу, когда ``NodeID`` собеседника ещё неизвестен.

        Используется для bootstrap: идентичность принимается после проверки
        самосогласованности ключа и, для TLS, привязки сертификата к ключу.
        Режим ``allow_bootstrap_trust = false`` запрещает такой доверительный
        контакт.
        """
        if expected_node_id is None and self._security.enabled and not self._config.allow_bootstrap_trust:
            raise HandshakeError("bootstrap trust is disabled by configuration")
        conn: Connection | None = None
        try:
            conn = await connect(
                host,
                port,
                ssl_context=self._security.client_context(),
                handshake_timeout=self._config.handshake_timeout_seconds,
                timeout=self._config.connect_timeout_seconds,
                request_timeout=self._config.request_timeout_seconds,
            )
            contact = await self._handshake(conn, expected=expected_node_id)
            self._connections[contact.node_id] = conn
            return conn, contact
        except (HandshakeError, SecurityError, RemoteError, TimeoutExpired, OSError):
            if conn is not None:
                await conn.close()
            raise

    async def _open(self, contact: Contact, expected_node_id: bytes) -> Connection:
        conn: Connection | None = None
        try:
            conn = await connect(
                contact.host,
                contact.port,
                ssl_context=self._security.client_context(),
                handshake_timeout=self._config.handshake_timeout_seconds,
                timeout=self._config.connect_timeout_seconds,
                request_timeout=self._config.request_timeout_seconds,
            )
            await self._handshake(conn, expected=expected_node_id)
            return conn
        except (HandshakeError, SecurityError, RemoteError, TimeoutExpired, OSError) as e:
            if conn is not None:
                await conn.close()
            if self._metrics is not None:
                self._metrics.emit(
                    "peer.dial_failed", peer=contact.short_id, address=contact.address,
                    error=type(e).__name__, detail=str(e),
                )
            raise

    async def _handshake(self, conn: Connection, *, expected: bytes | None) -> Contact:
        """Проверить TLS-слой и обменяться ``HELLO`` на исходящем соединении."""
        peer_id: bytes | None = None
        if self._security.enabled:
            peer_id = self._security.verify_peer(conn, expected)
        try:
            reply = await conn.request(
                MsgType.HELLO,
                payload=codec.encode_payload(self.hello_payload()),
                timeout=self._config.handshake_timeout_seconds,
                expected_type=MsgType.HELLO_OK,
            )
        except RemoteError as e:
            # Удалённая сторона отвергла нашу идентичность.
            if e.code == ErrorCode.IDENTITY_MISMATCH:
                raise HandshakeError(f"peer rejected our identity: {e.detail}") from e
            raise
        except ConnectionError as e:
            # Соединение закрыто до получения HELLO_OK: рукопожатие не состоялось.
            raise HandshakeError("connection closed during handshake") from e
        contact = self._validate_hello(reply, conn, expected=expected)
        if peer_id is not None and peer_id != contact.node_id:
            raise HandshakeError("HELLO identity differs from the TLS certificate identity")
        self._attach_dispatcher(conn, contact)
        if self._metrics is not None:
            self._metrics.emit(
                "peer.dial", peer=contact.short_id, address=contact.address,
                tls=conn.tls_version, cipher=conn.tls_cipher,
            )
        return contact

    # -------------------------------------------------------------- validation

    def _validate_hello(
        self,
        frame: Frame,
        conn: Connection,
        *,
        expected: bytes | None,
    ) -> Contact:
        try:
            obj = codec.decode_mapping(frame.payload)
        except ProtocolError as e:
            raise HandshakeError(f"HELLO payload is not a map: {e}") from e
        if int(obj.get("version", 0)) != HELLO_VERSION:
            raise HandshakeError("unsupported HELLO version")
        node_id = obj.get("node_id")
        key = obj.get("key")
        host = obj.get("host")
        port = obj.get("port")
        if not isinstance(node_id, bytes) or not isinstance(key, bytes):
            raise HandshakeError("HELLO node_id/key must be byte strings")
        if not isinstance(host, str) or not isinstance(port, int):
            raise HandshakeError("HELLO host/port must be str/int")

        if node_id == self._identity.node_id:
            raise HandshakeError("refusing self-connection")
        if len(node_id) != self._config.node_id_bytes:
            raise HandshakeError(
                f"HELLO node_id length {len(node_id)} != configured {self._config.node_id_bytes}"
            )
        if not verify_node_id(node_id, key, len(node_id) * 8):
            raise HandshakeError("HELLO NodeID does not match the presented public key")
        if expected is not None and node_id != expected:
            raise HandshakeError(
                f"peer NodeID {node_id.hex()[:12]} != expected {expected.hex()[:12]}"
            )

        address_host, address_port = self._contact_address(conn, host, port)
        try:
            return Contact(
                node_id=node_id,
                public_key_der=key,
                host=address_host,
                port=address_port,
            )
        except Exception as e:
            raise HandshakeError(f"invalid peer contact: {e}") from e

    def _contact_address(self, conn: Connection, host: str, port: int) -> tuple[str, int]:
        peer_host, peer_port = conn.peer_address
        if host in _UNSPECIFIED_HOSTS or not is_valid_host(host) or not is_valid_port(port):
            if not is_valid_host(peer_host) or not is_valid_port(peer_port):
                raise HandshakeError(f"cannot determine peer address: {peer_host}:{peer_port}")
            return peer_host, peer_port
        return host, port

    async def _reject(self, conn: Connection, detail: str) -> None:
        log.warning("rejecting peer %s: %s", conn.peer_address, detail)
        try:
            await conn.send(
                Frame(
                    type=MsgType.ERROR,
                    request_id=Frame.new_request_id(),
                    payload=codec.encode_payload({"code": 0x08, "detail": detail}),
                    flags=FLAG_ERROR,
                )
            )
        except Exception:  # соединение может быть уже закрыто
            pass
        if self._metrics is not None:
            self._metrics.emit("peer.rejected", detail=detail)
        # Дать удалённой стороне прочитать кадр ERROR до закрытия соединения.
        await asyncio.sleep(0.05)

    # ----------------------------------------------------------------- cleanup

    def forget(self, node_id: bytes) -> None:
        conn = self._connections.pop(node_id, None)
        if conn is not None and not conn.closed:
            asyncio.create_task(conn.close())

    async def close_peer(self, node_id: bytes) -> None:
        conn = self._connections.pop(node_id, None)
        if conn is not None:
            await conn.close()

    async def close_all(self) -> None:
        conns = list(self._connections.values())
        self._connections.clear()
        await asyncio.gather(*(c.close() for c in conns), return_exceptions=True)

    def snapshot(self) -> dict[str, Any]:
        return {
            "open_connections": self.open_connections,
            "cached_peers": [node_id.hex() for node_id in self._connections],
            "local_address": f"{self._advertise_host}:{self.bound_port}",
        }
