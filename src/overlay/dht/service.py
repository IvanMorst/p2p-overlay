"""Серверная сторона DHT: обработка входящих RPC.

Сервис не имеет доступа к k-bucket вызывающего кода: он получает таблицу
маршрутизации и (на следующем этапе) локальное хранилище записей через
конструктор, а прикладной слой обращается к DHT только через фасад узла.
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import NodeConfig
from ..identity import Identity
from ..metrics import EventRecorder
from ..transport import codec
from ..transport.frame import FLAG_ERROR, FLAG_RESPONSE, Frame, MsgType
from ..transport.tcp import Connection
from .contact import Contact
from .routing import RoutingTable

log = logging.getLogger(__name__)


class DhtService:
    """Диспетчер входящих DHT-запросов."""

    def __init__(
        self,
        identity: Identity,
        table: RoutingTable,
        config: NodeConfig,
        *,
        metrics: EventRecorder | None = None,
    ) -> None:
        self._identity = identity
        self._table = table
        self._config = config
        self._metrics = metrics
        self.requests_in = 0
        self.requests_out = 0
        self.rejected = 0

    # --------------------------------------------------------------- dispatch

    async def handle(self, conn: Connection, peer: Contact | None, frame: Frame) -> None:
        """Обработать кадр; неизвестные типы получают ``ERROR``."""
        self.requests_in += 1
        try:
            if frame.type == MsgType.PING:
                await self._on_ping(conn, peer, frame)
            elif frame.type == MsgType.FIND_NODE_REQUEST:
                await self._on_find_node(conn, peer, frame)
            else:
                await self._send_error(conn, frame, 0x02, f"unsupported type 0x{frame.type:02x}")
        except Exception as e:
            log.exception("failed to handle frame 0x%02x", frame.type)
            self.rejected += 1
            await self._send_error(conn, frame, 0x07, f"{type(e).__name__}: {e}")

    # --------------------------------------------------------------- handlers

    async def _on_ping(self, conn: Connection, peer: Contact | None, frame: Frame) -> None:
        await self._reply(
            conn,
            frame,
            MsgType.PONG,
            {"ok": True, "node_id": self._identity.node_id},
        )

    async def _on_find_node(self, conn: Connection, peer: Contact | None, frame: Frame) -> None:
        obj = codec.decode_mapping(frame.payload)
        target = obj.get("target")
        if not isinstance(target, bytes) or len(target) != len(self._identity.node_id):
            raise ValueError("FIND_NODE target has invalid length")
        limit = obj.get("count")
        if not isinstance(limit, int) or not 1 <= limit <= self._config.k_bucket_size:
            limit = self._config.k_bucket_size
        contacts = self._table.closest(target, limit)
        await self._reply(
            conn,
            frame,
            MsgType.FIND_NODE_RESPONSE,
            {
                "contacts": [c.to_cbor() for c in contacts],
                "node_id": self._identity.node_id,
                "total": len(self._table),
            },
        )

    # ---------------------------------------------------------------- helpers

    async def _reply(
        self, conn: Connection, request: Frame, msg_type: int, payload: dict[str, Any]
    ) -> None:
        await conn.send(
            Frame(
                type=msg_type,
                request_id=request.request_id,
                payload=codec.encode_payload(payload),
                flags=FLAG_RESPONSE,
            )
        )
        self.requests_out += 1

    async def _send_error(
        self, conn: Connection, request: Frame, code: int, detail: str
    ) -> None:
        try:
            await conn.send(
                Frame(
                    type=MsgType.ERROR,
                    request_id=request.request_id,
                    payload=codec.encode_payload({"code": code, "detail": detail}),
                    flags=FLAG_ERROR,
                )
            )
        except Exception:  # соединение могло закрыться
            pass
