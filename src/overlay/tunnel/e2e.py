"""End-to-end защита прикладных данных поверх туннеля.

Ретрансляторы видят только ``TUNNEL_DATA`` с непрозрачным ciphertext: между
отправителем и получателем устанавливается отдельная TLS 1.3-сессия, кадры
которой пересылаются как полезная нагрузка туннеля. Поэтому hop-by-hop TLS
ретрансляторов не даёт им доступа к прикладному тексту.

TLS-сессия реализована через ``ssl.MemoryBIO``: протокол не привязан к сокету
и работает поверх любой функции доставки байтов (в нашем случае — туннеля).
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Awaitable, Callable
from typing import Any

from ..errors import TunnelError
from ..security.trust import PeerIdentity, verify_peer_certificate
from ..transport import codec

log = logging.getLogger(__name__)

MAX_PLAINTEXT_CHUNK = 60 * 1024
LENGTH_PREFIX = 4

CiphertextSender = Callable[[bytes], Awaitable[None]]


class E2EChannel:
    """TLS 1.3-сессия поверх абстрактного байтового канала."""

    def __init__(
        self,
        context: ssl.SSLContext,
        *,
        server_side: bool,
    ) -> None:
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._ssl = context.wrap_bio(
            self._incoming, self._outgoing, server_side=server_side, server_hostname=None
        )
        self._handshake_done = False
        self._closed = False

    @property
    def handshake_complete(self) -> bool:
        return self._handshake_done

    @property
    def closed(self) -> bool:
        return self._closed

    def start(self) -> bytes:
        """Начать рукопожатие (клиент) и вернуть байты для отправки."""
        if not self._handshake_done:
            self._progress()
        return self._drain()

    def feed(self, ciphertext: bytes) -> tuple[bytes, bytes]:
        """Принять ciphertext; вернуть (открытый текст, байты для отправки)."""
        if not ciphertext:
            return b"", self._drain()
        try:
            self._incoming.write(ciphertext)
        except ssl.SSLError as e:
            self._closed = True
            raise TunnelError(f"e2e channel rejected ciphertext: {e}") from e
        if not self._handshake_done:
            self._progress()
            return b"", self._drain()
        plaintext = self._read_plaintext()
        return plaintext, self._drain()

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self._handshake_done:
            raise TunnelError("e2e handshake is not complete")
        if len(plaintext) > MAX_PLAINTEXT_CHUNK:
            raise TunnelError("e2e chunk is too large")
        try:
            self._ssl.write(plaintext)
        except ssl.SSLError as e:
            self._closed = True
            raise TunnelError(f"e2e encryption failed: {e}") from e
        return self._drain()

    def peer_certificate_der(self) -> bytes | None:
        try:
            raw = self._ssl.getpeercert(binary_form=True)
        except (ValueError, ssl.SSLError):
            return None
        return raw if isinstance(raw, bytes) else None

    @property
    def tls_version(self) -> str:
        try:
            return self._ssl.version() or "unknown"
        except ssl.SSLError:
            return "unknown"

    # ---------------------------------------------------------------- private

    def _progress(self) -> None:
        try:
            self._ssl.do_handshake()
            self._handshake_done = True
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError as e:
            self._closed = True
            raise TunnelError(f"e2e handshake failed: {e}") from e

    def _read_plaintext(self) -> bytes:
        chunks = bytearray()
        while True:
            try:
                chunk = self._ssl.read(MAX_PLAINTEXT_CHUNK)
            except ssl.SSLWantReadError:
                break
            except ssl.SSLZeroReturnError:
                self._closed = True
                break
            except ssl.SSLError as e:
                self._closed = True
                raise TunnelError(f"e2e decryption failed: {e}") from e
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)

    def _drain(self) -> bytes:
        try:
            data = self._outgoing.read()
        except ssl.SSLError:
            return b""
        return data or b""


class E2ESession:
    """Кадрирование и асинхронный обмен сообщениями поверх ``E2EChannel``."""

    def __init__(
        self,
        channel: E2EChannel,
        send_ciphertext: CiphertextSender,
        *,
        node_id_bits: int,
        expected_peer: bytes | None = None,
    ) -> None:
        self._channel = channel
        self._send_ciphertext = send_ciphertext
        self._node_id_bits = node_id_bits
        self._expected_peer = expected_peer
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._ready = asyncio.Event()
        self._buffer = bytearray()
        self._peer: PeerIdentity | None = None

    # ------------------------------------------------------------- свойства

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def peer(self) -> PeerIdentity | None:
        return self._peer

    @property
    def tls_version(self) -> str:
        return self._channel.tls_version

    # ---------------------------------------------------------- рукопожатие

    async def start(self, timeout: float) -> None:
        """Клиентская сторона: инициировать рукопожатие и дождаться готовности."""
        outgoing = self._channel.start()
        if outgoing:
            await self._send_ciphertext(outgoing)
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)

    def _verify_peer(self) -> None:
        der = self._channel.peer_certificate_der()
        if der is None:
            raise TunnelError("e2e peer did not present a certificate")
        peer = verify_peer_certificate(
            der,
            node_id_bits=self._node_id_bits,
            expected_node_id=self._expected_peer,
        )
        if self._channel.tls_version != "TLSv1.3":
            raise TunnelError(f"unexpected e2e TLS version: {self._channel.tls_version}")
        self._peer = peer

    # --------------------------------------------------------------- приём

    async def feed(self, ciphertext: bytes) -> None:
        """Принять кадр туннеля и разобрать открытый текст."""
        plaintext, outgoing = self._channel.feed(ciphertext)
        if outgoing:
            await self._send_ciphertext(outgoing)
        if self._channel.handshake_complete and not self._ready.is_set():
            self._verify_peer()
            self._ready.set()
        if plaintext:
            self._buffer.extend(plaintext)
            self._drain_buffer()

    def _drain_buffer(self) -> None:
        while len(self._buffer) >= LENGTH_PREFIX:
            size = int.from_bytes(self._buffer[:LENGTH_PREFIX], "big")
            end = LENGTH_PREFIX + size
            if len(self._buffer) < end:
                break
            chunk = bytes(self._buffer[LENGTH_PREFIX:end])
            del self._buffer[:end]
            try:
                message = codec.decode_mapping(chunk)
            except Exception as e:
                log.warning("cannot decode e2e message: %s", e)
                continue
            self._queue.put_nowait(message)

    async def receive(self, timeout: float) -> dict[str, Any]:
        return await asyncio.wait_for(self._queue.get(), timeout=timeout)

    async def wait_ready(self, timeout: float) -> None:
        """Дождаться завершения рукопожатия."""
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)

    # ------------------------------------------------------------- передача

    async def send(self, message: dict[str, Any]) -> None:
        if not self._ready.is_set():
            raise TunnelError("e2e session is not established")
        payload = codec.encode_payload(message)
        frame = len(payload).to_bytes(LENGTH_PREFIX, "big") + payload
        ciphertext = self._channel.encrypt(frame)
        if ciphertext:
            await self._send_ciphertext(ciphertext)
