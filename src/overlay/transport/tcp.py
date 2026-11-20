"""TCP-транспорт: сервер, клиент, потоковый декодер, корреляция RPC.

Транспорт не знает о DHT, идентичности и туннелях. Всё вышележащее использует
``Connection.send()``, ``Connection.request()`` и колбэк ``on_frame``.

Границы кадров восстанавливаются потоковым декодером: один ``read()`` не
обязан совпадать с одним кадром.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import ssl
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..errors import ProtocolError, RemoteError, TimeoutExpired
from . import codec
from .frame import (
    FLAG_ERROR,
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
    BadType,
    BadVersion,
    ErrorCode,
    Frame,
    FrameError,
    FrameHeader,
    MsgType,
    PayloadTooLarge,
)

log = logging.getLogger(__name__)

_READ_SIZE = 65_536
_MAX_BUFFER = HEADER_SIZE + MAX_FRAME_PAYLOAD


class StreamDecoder:
    """Инкрементальный декодер кадров поверх TCP-потока."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[Frame]:
        """Добавить байты и вернуть все полностью собранные кадры.

        Частичный заголовок и частичный payload остаются в буфере. Значение
        ``payload_length`` проверяется до выделения памяти под payload.
        """
        self._buf.extend(chunk)
        frames: list[Frame] = []
        while True:
            if len(self._buf) < HEADER_SIZE:
                break
            header = FrameHeader.unpack(bytes(self._buf[:HEADER_SIZE]))
            if header.version != PROTOCOL_VERSION:
                raise BadVersion(header.version)
            try:
                MsgType(header.type)
            except ValueError as e:
                raise BadType(header.type) from e
            if header.payload_length > MAX_FRAME_PAYLOAD:
                raise PayloadTooLarge(header.payload_length)
            total = HEADER_SIZE + header.payload_length
            if len(self._buf) < total:
                if len(self._buf) > _MAX_BUFFER:
                    raise PayloadTooLarge(len(self._buf))
                break
            payload = bytes(self._buf[HEADER_SIZE:total])
            del self._buf[:total]
            frames.append(
                Frame(
                    type=header.type,
                    request_id=header.request_id,
                    payload=payload,
                    flags=header.flags,
                    version=header.version,
                )
            )
        return frames

    @property
    def buffered(self) -> int:
        return len(self._buf)


@dataclass(slots=True)
class PendingRequest:
    """Ожидающий ответа RPC; привязан к одному request_id."""

    future: asyncio.Future[Frame]
    expected_type: int | None


class Connection:
    """Одно TCP-соединение (при необходимости защищённое TLS 1.3)."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        inbound: bool = False,
        request_timeout: float = 5.0,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.inbound = inbound
        self.request_timeout = request_timeout
        self.decoder = StreamDecoder()
        self.session_id = secrets.token_bytes(16)
        self._pending: dict[bytes, PendingRequest] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()
        self._on_frame: Callable[[Frame], Awaitable[None]] | None = None
        self._closing = False
        self._seen_requests: set[bytes] = set()
        self._seen_order: deque[bytes] = deque(maxlen=65_536)
        self.replays_rejected = 0
        self.frames_in = 0
        self.frames_out = 0

    # --- регистрация обработчика -------------------------------------------

    def set_handler(self, handler: Callable[[Frame], Awaitable[None]]) -> None:
        self._on_frame = handler

    # --- свойства ----------------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def peer_address(self) -> tuple[str, int]:
        peer = self.writer.get_extra_info("peername")
        if isinstance(peer, tuple) and len(peer) >= 2:
            return str(peer[0]), int(peer[1])
        return "", 0

    @property
    def tls_object(self) -> ssl.SSLObject | None:
        obj = self.writer.get_extra_info("ssl_object")
        return obj if isinstance(obj, ssl.SSLObject) else None

    @property
    def tls_version(self) -> str:
        obj = self.tls_object
        return (obj.version() or "unknown") if obj is not None else "plain"

    @property
    def tls_cipher(self) -> str:
        obj = self.tls_object
        if obj is None:
            return "plain"
        cipher = obj.cipher()
        return cipher[0] if cipher else "unknown"

    @property
    def peer_certificate_der(self) -> bytes | None:
        """DER-сертификат удалённой стороны, если соединение защищено TLS."""
        obj = self.tls_object
        if obj is None:
            return None
        raw = obj.getpeercert(binary_form=True)
        return raw if isinstance(raw, bytes) else None

    # --- жизненный цикл ----------------------------------------------------

    def start(self) -> None:
        """Запустить цикл чтения; повторный вызов безопасен."""
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_loop(), name="conn-reader")

    async def wait_closed(self) -> None:
        """Дождаться закрытия соединения (с любой стороны)."""
        await self._closed.wait()

    async def _read_loop(self) -> None:
        try:
            while not self._closed.is_set():
                chunk = await self.reader.read(_READ_SIZE)
                if not chunk:
                    break
                for frame in self.decoder.feed(chunk):
                    self.frames_in += 1
                    await self._dispatch(frame)
        except asyncio.CancelledError:
            raise
        except FrameError as e:
            # Нарушение кадрирования: соединение закрывается, узел продолжает работу.
            log.warning("frame error from %s: %s", self.peer_address, e)
        except ssl.SSLError as e:
            log.warning("tls error from %s: %s", self.peer_address, e)
        except (ConnectionError, OSError) as e:
            log.debug("connection lost %s: %s", self.peer_address, e)
        except Exception:
            log.exception("reader loop failed")
        finally:
            self._closed.set()
            self._fail_pending(ConnectionError("connection closed"))

    def _fail_pending(self, exc: BaseException) -> None:
        for pending in self._pending.values():
            if not pending.future.done():
                pending.future.set_exception(exc)
        self._pending.clear()

    async def _dispatch(self, frame: Frame) -> None:
        pending = self._pending.pop(frame.request_id, None)
        if pending is not None:
            if pending.future.done():
                return
            if frame.is_error:
                pending.future.set_exception(_remote_error(frame))
                return
            if pending.expected_type is not None and frame.type != pending.expected_type:
                pending.future.set_exception(
                    ProtocolError(
                        f"unexpected response type 0x{frame.type:02x}, "
                        f"expected 0x{pending.expected_type:02x}",
                    )
                )
                return
            pending.future.set_result(frame)
            return
        if frame.is_response:
            # Ответ без ожидающего запроса: не выполняем прикладных действий.
            log.debug("late response id=%s from %s", frame.request_id.hex(), self.peer_address)
            return
        if frame.request_id in self._seen_requests:
            # Повтор кадра в текущей сессии: прикладное действие не выполняется.
            self.replays_rejected += 1
            log.warning(
                "replay detected: request_id=%s from %s",
                frame.request_id.hex(),
                self.peer_address,
            )
            await self._reject_replay(frame)
            return
        self._remember_request(frame.request_id)
        if self._on_frame is None:
            log.debug("unhandled frame type=%s id=%s", frame.type, frame.request_id.hex())
            return
        try:
            await self._on_frame(frame)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("handler failed for type 0x%02x", frame.type)

    # --- отправка ----------------------------------------------------------

    def _remember_request(self, request_id: bytes) -> None:
        if len(self._seen_order) == self._seen_order.maxlen:
            oldest = self._seen_order[0]
            self._seen_requests.discard(oldest)
        self._seen_order.append(request_id)
        self._seen_requests.add(request_id)

    async def _reject_replay(self, frame: Frame) -> None:
        with contextlib.suppress(Exception):
            await self.send(
                Frame(
                    type=MsgType.ERROR,
                    request_id=frame.request_id,
                    payload=codec.encode_payload(
                        {"code": int(ErrorCode.REPLAY_DETECTED), "detail": "duplicate request_id"}
                    ),
                    flags=FLAG_ERROR,
                )
            )

    async def send(self, frame: Frame) -> None:
        if self._closed.is_set():
            raise ConnectionError("connection closed")
        self.writer.write(frame.encode())
        self.frames_out += 1
        await self.writer.drain()

    async def send_raw(self, data: bytes) -> None:
        """Отправить уже закодированные байты (используется e2e-каналом)."""
        if self._closed.is_set():
            raise ConnectionError("connection closed")
        self.writer.write(data)
        await self.writer.drain()

    async def request(
        self,
        msg_type: int,
        payload: bytes = b"",
        *,
        timeout: float | None = None,
        expected_type: int | None = None,
    ) -> Frame:
        """Отправить запрос и дождаться ответа с тем же request_id."""
        frame = Frame(type=msg_type, request_id=Frame.new_request_id(), payload=payload)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Frame] = loop.create_future()
        self._pending[frame.request_id] = PendingRequest(future=fut, expected_type=expected_type)
        try:
            await self.send(frame)
            return await asyncio.wait_for(fut, timeout=timeout or self.request_timeout)
        except TimeoutError as e:
            raise TimeoutExpired(f"timeout waiting for 0x{msg_type:02x} response") from e
        finally:
            self._pending.pop(frame.request_id, None)

    # --- закрытие ----------------------------------------------------------

    async def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._closed.set()
        self._fail_pending(ConnectionError("connection closed"))
        if self._reader_task is not None and self._reader_task is not asyncio.current_task():
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader_task
        self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()


def _remote_error(frame: Frame) -> RemoteError:
    code: int | None = None
    detail = ""
    try:
        obj = codec.decode_payload(frame.payload)
        if isinstance(obj, dict):
            raw_code = obj.get("code")
            if isinstance(raw_code, int):
                code = raw_code
            raw_detail = obj.get("detail")
            if isinstance(raw_detail, str):
                detail = raw_detail
    except Exception:  # payload ошибки может быть не-CBOR; это не повод падать
        pass
    return RemoteError(f"remote error code={code} detail={detail!r}", code=code, detail=detail)


ConnectionHandler = Callable[[Connection], Awaitable[None]]


async def serve(
    host: str,
    port: int,
    handler: ConnectionHandler,
    *,
    ssl_context: ssl.SSLContext | None = None,
    handshake_timeout: float = 10.0,
    request_timeout: float = 5.0,
) -> asyncio.Server:
    """Поднять TCP-сервер; для каждого соединения вызывается ``handler``."""

    async def _on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = Connection(reader, writer, inbound=True, request_timeout=request_timeout)
        conn.start()
        try:
            await handler(conn)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("connection handler failed")
        finally:
            await conn.close()

    kwargs: dict[str, Any] = {}
    if ssl_context is not None:
        kwargs["ssl"] = ssl_context
        kwargs["ssl_handshake_timeout"] = handshake_timeout
    return await asyncio.start_server(_on_client, host=host, port=port, **kwargs)


async def connect(
    host: str,
    port: int,
    *,
    ssl_context: ssl.SSLContext | None = None,
    handshake_timeout: float = 10.0,
    timeout: float = 5.0,
    request_timeout: float = 5.0,
) -> Connection:
    """Установить TCP-соединение (при необходимости с TLS-рукопожатием)."""
    kwargs: dict[str, Any] = {}
    if ssl_context is not None:
        kwargs["ssl"] = ssl_context
        kwargs["ssl_handshake_timeout"] = handshake_timeout
        kwargs["server_hostname"] = host
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=host, port=port, **kwargs), timeout=timeout
    )
    conn = Connection(reader, writer, inbound=False, request_timeout=request_timeout)
    conn.start()
    return conn
