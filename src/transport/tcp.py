from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .frame import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    BadType,
    BadVersion,
    Frame,
    FrameError,
    FrameHeader,
    MsgType,
    PayloadTooLarge,
    PROTOCOL_VERSION,
    ShortHeader,
)

log = logging.getLogger(__name__)


class StreamDecoder:
    """Инкрементальный декодер кадров поверх TCP-потока."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[Frame]:
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
                break
            payload = bytes(self._buf[HEADER_SIZE:total])
            del self._buf[:total]
            frames.append(Frame(
                type=header.type,
                request_id=header.request_id,
                payload=payload,
                flags=header.flags,
                version=header.version,
            ))
        return frames

    @property
    def buffered(self) -> int:
        return len(self._buf)


@dataclass
class PendingRequest:
    future: asyncio.Future
    expected_type: int | None


class Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.decoder = StreamDecoder()
        self._pending: dict[bytes, PendingRequest] = {}
        self._reader_task: asyncio.Task | None = None
        self._closed = asyncio.Event()
        self._on_frame: Callable[[Frame], Awaitable[None]] | None = None

    def set_handler(self, handler: Callable[[Frame], Awaitable[None]]) -> None:
        self._on_frame = handler

    def start(self) -> None:
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while not self._closed.is_set():
                chunk = await self.reader.read(4096)
                if not chunk:
                    break
                for frame in self.decoder.feed(chunk):
                    await self._dispatch(frame)
        except FrameError as e:
            log.warning("frame error: %s", e)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("reader loop failed")
        finally:
            self._closed.set()
            for pending in self._pending.values():
                if not pending.future.done():
                    pending.future.set_exception(ConnectionError("connection closed"))
            self._pending.clear()

    async def _dispatch(self, frame: Frame) -> None:
        pending = self._pending.pop(frame.request_id, None)
        if pending is not None and not pending.future.done():
            pending.future.set_result(frame)
            return
        if self._on_frame is not None:
            await self._on_frame(frame)
        else:
            log.debug("unhandled frame type=%s id=%s", frame.type, frame.request_id.hex())

    async def send(self, frame: Frame) -> None:
        if self._closed.is_set():
            raise ConnectionError("connection closed")
        self.writer.write(frame.encode())
        await self.writer.drain()

    async def request(
        self,
        msg_type: int,
        payload: bytes = b"",
        *,
        timeout: float = 5.0,
        expected_type: int | None = None,
    ) -> Frame:
        frame = Frame(type=msg_type, request_id=Frame.new_request_id(), payload=payload)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[frame.request_id] = PendingRequest(future=fut, expected_type=expected_type)
        try:
            await self.send(frame)
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            raise
        finally:
            self._pending.pop(frame.request_id, None)

    async def close(self) -> None:
        self._closed.set()
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass

    @property
    def closed(self) -> bool:
        return self._closed.is_set()


ConnectionHandler = Callable[[Connection], Awaitable[None]]


async def serve(host: str, port: int, handler: ConnectionHandler) -> asyncio.AbstractServer:
    async def _on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = Connection(reader, writer)
        conn.start()
        try:
            await handler(conn)
        finally:
            await conn.close()

    return await asyncio.start_server(_on_client, host=host, port=port)


async def connect(host: str, port: int) -> Connection:
    reader, writer = await asyncio.open_connection(host=host, port=port)
    conn = Connection(reader, writer)
    conn.start()
    return conn