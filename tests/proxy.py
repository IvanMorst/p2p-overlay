"""Прозрачный TCP-прокси для проверки конфиденциальности трафика.

Прокси не является частью продукта: он пересылает байты между клиентом и
сервером и записывает обе стороны обмена. Это замена контрольному pcap,
переносимая между платформами: то, что видит прокси, видит и пассивный
наблюдатель канала.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field

TLS_APPLICATION_DATA = 0x17
TLS_HANDSHAKE = 0x16


@dataclass(slots=True)
class RecordingProxy:
    target_host: str = "127.0.0.1"
    target_port: int = 0
    client_to_server: bytearray = field(default_factory=bytearray)
    server_to_client: bytearray = field(default_factory=bytearray)
    connections: int = 0
    _server: asyncio.Server | None = None
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)
    port: int = 0

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        sockets = self._server.sockets
        if sockets:
            self.port = int(sockets[0].getsockname()[1])
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except OSError:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return

        async def pump(
            src: asyncio.StreamReader, dst: asyncio.StreamWriter, sink: bytearray
        ) -> None:
            try:
                while True:
                    chunk = await src.read(65_536)
                    if not chunk:
                        break
                    sink.extend(chunk)
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.close()

        own = {
            asyncio.create_task(pump(reader, upstream_writer, self.client_to_server)),
            asyncio.create_task(pump(upstream_reader, writer, self.server_to_client)),
        }
        self._tasks |= own
        try:
            await asyncio.gather(*own, return_exceptions=True)
        finally:
            self._tasks -= own
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                upstream_writer.close()

    def reset(self) -> None:
        self.client_to_server.clear()
        self.server_to_client.clear()

    def contains(self, needle: bytes) -> bool:
        return needle in self.client_to_server or needle in self.server_to_client


def split_tls_records(buffer: bytes) -> list[tuple[int, bytes]]:
    """Разобрать поток TLS-записей: (content_type, payload)."""
    records: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 5 <= len(buffer):
        content_type = buffer[offset]
        length = int.from_bytes(buffer[offset + 3 : offset + 5], "big")
        end = offset + 5 + length
        if end > len(buffer):
            break
        records.append((content_type, bytes(buffer[offset:end])))
        offset = end
    return records


def application_records(buffer: bytes) -> list[bytes]:
    """Выбрать записи application_data (0x17) из потока."""
    return [raw for kind, raw in split_tls_records(buffer) if kind == TLS_APPLICATION_DATA]
