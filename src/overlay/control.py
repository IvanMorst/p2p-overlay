"""Локальный интерфейс управления работающим узлом.

Не является частью оверлейного протокола: сокет слушает только петлевой
интерфейс (по умолчанию выключен, ``control_port = 0``) и используется
консольным интерфейсом, сценариями эксперимента и тестами, чтобы не поднимать
второй узел с тем же ``NodeID``.

Формат: 4 байта длины (big-endian) + канонический CBOR-словарь.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING, Any

from .dht.record import record_key_for_node
from .transport import codec

if TYPE_CHECKING:  # pragma: no cover - только для аннотаций
    from .node import Node

log = logging.getLogger(__name__)

MAX_CONTROL_MESSAGE = 4 * 1024 * 1024


class ControlError(Exception):
    """Ошибка локального интерфейса управления."""


class ControlServer:
    """Принимает команды локального управления и вызывает методы узла."""

    def __init__(self, node: Node, host: str = "127.0.0.1", port: int = 0) -> None:
        self._node = node
        self._host = host
        self._port = port
        self._server: asyncio.Server | None = None
        self._bound_port = 0

    @property
    def port(self) -> int:
        return self._bound_port

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        sockets = self._server.sockets
        if sockets:
            self._bound_port = int(sockets[0].getsockname()[1])
        log.info("control interface on %s:%d", self._host, self._bound_port)
        return self._bound_port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                header = await reader.readexactly(4)
                size = int.from_bytes(header, "big")
                if not 0 < size <= MAX_CONTROL_MESSAGE:
                    break
                body = await reader.readexactly(size)
                try:
                    request = codec.decode_mapping(body)
                    response = await self._dispatch(request)
                except Exception as e:  # ошибка команды не должна ронять узел
                    response = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                payload = codec.encode_payload(response)
                writer.write(len(payload).to_bytes(4, "big") + payload)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("control connection failed")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        command = request.get("cmd")
        if not isinstance(command, str):
            raise ControlError("command must be a string")
        handler = getattr(self, f"_cmd_{command}", None)
        if handler is None:
            raise ControlError(f"unknown command: {command}")
        result = await handler(request)
        if isinstance(result, dict):
            return {"ok": True, **result}
        return {"ok": True, "result": result}

    # ------------------------------------------------------------- команды

    async def _cmd_info(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._node.get_network_state()

    async def _cmd_table(self, request: dict[str, Any]) -> dict[str, Any]:
        return {
            "stats": self._node.table.stats(),
            "buckets": self._node.table.bucket_table(),
        }

    async def _cmd_contacts(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"contacts": [c.to_public_dict() for c in self._node.table.all_contacts()]}

    async def _cmd_lookup(self, request: dict[str, Any]) -> dict[str, Any]:
        target = _require_node_id(request, "node_id")
        result = await self._node.lookup_node(target)
        return {"lookup": result.to_dict()}

    async def _cmd_ping(self, request: dict[str, Any]) -> dict[str, Any]:
        target = _require_node_id(request, "node_id")
        contact = self._node.table.get(target)
        if contact is None:
            raise ControlError("node is not in the routing table; run lookup first")
        alive = await self._node.rpc.ping(contact)
        return {"alive": alive, "node_id": target.hex()}

    # ------------------------------------------------------- записи DHT

    async def _cmd_put(self, request: dict[str, Any]) -> dict[str, Any]:
        """Опубликовать собственную адресную запись."""
        report = await self._node.publish_self()
        return {"publish": report.to_dict()}

    async def _cmd_get(self, request: dict[str, Any]) -> dict[str, Any]:
        """Найти адресную запись узла по его NodeID."""
        target = _require_node_id(request, "node_id")
        record = await self._node.get_record(record_key_for_node(target))
        if record is None:
            raise ControlError("address record not found")
        return {
            "record": {
                "node_id": record.node_id.hex(),
                "addresses": [str(a) for a in record.addresses],
                "sequence_number": record.sequence_number,
                "issued_at": record.issued_at,
                "expires_at": record.expires_at,
                "ttl_left_s": round(record.expires_at - time.time(), 3),
            }
        }

    async def _cmd_records(self, request: dict[str, Any]) -> dict[str, Any]:
        return {
            "stats": self._node.storage.stats(),
            "records": self._node.storage.snapshot(),
        }


async def _read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await reader.readexactly(4)
    size = int.from_bytes(header, "big")
    if not 0 < size <= MAX_CONTROL_MESSAGE:
        raise ControlError("invalid control message size")
    body = await reader.readexactly(size)
    return codec.decode_mapping(body)


class ControlClient:
    """Клиент локального интерфейса управления."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    @classmethod
    async def connect(cls, host: str = "127.0.0.1", port: int = 0) -> ControlClient:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer)

    async def request(self, command: str, **args: Any) -> dict[str, Any]:
        payload = codec.encode_payload({"cmd": command, **args})
        self._writer.write(len(payload).to_bytes(4, "big") + payload)
        await self._writer.drain()
        response = await _read_message(self._reader)
        if not response.get("ok", False):
            raise ControlError(str(response.get("error", "unknown control error")))
        return response

    async def close(self) -> None:
        self._writer.close()
        with contextlib.suppress(Exception):
            await self._writer.wait_closed()

    async def __aenter__(self) -> ControlClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


def _require_node_id(request: dict[str, Any], field: str) -> bytes:
    raw = request.get(field)
    if not isinstance(raw, str):
        raise ControlError(f"{field} must be a hex string")
    try:
        value = bytes.fromhex(raw)
    except ValueError as e:
        raise ControlError(f"{field} is not valid hex: {e}") from e
    if not value:
        raise ControlError(f"{field} must not be empty")
    return value


def parse_node_id(text: str) -> bytes:
    """Разобрать идентификатор из CLI: полный hex или однозначный префикс."""
    value = text.strip().lower().replace("0x", "")
    if not value:
        raise ControlError("empty node id")
    if len(value) % 2 == 1:
        value = "0" + value
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise ControlError(f"invalid node id: {text!r}") from e
