"""Прикладной сервис текстовых сообщений поверх туннеля.

Свойства (раздел 13.1 ТЗ):

* разрешение получателя по ``NodeID`` через подписанную запись DHT;
* построение туннеля и передача только через него;
* end-to-end защита содержимого (TLS-сессия внутри туннеля);
* подтверждение доставки;
* уникальный ``message_id`` и защита от повторной обработки;
* локальная история отправки и приёма;
* диагностический вывод маршрута без раскрытия ключей.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..errors import TunnelError
from ..security.replay import ReplayGuard

if TYPE_CHECKING:  # pragma: no cover - только для аннотаций
    from ..node import Node
    from ..tunnel.e2e import E2ESession

log = logging.getLogger(__name__)

KIND_MESSAGE = "app_message"
KIND_ACK = "app_ack"


@dataclass(slots=True)
class MessageRecord:
    """Запись локальной истории отправки или приёма."""

    message_id: bytes
    direction: str
    peer: str
    text: str
    status: str
    at: float
    tunnel_id: str | None = None
    hops: list[str] = field(default_factory=list)
    latency_s: float | None = None
    attempts: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id.hex(),
            "direction": self.direction,
            "peer": self.peer,
            "text": self.text,
            "status": self.status,
            "at": round(self.at, 6),
            "tunnel_id": self.tunnel_id,
            "hops": list(self.hops),
            "latency_s": round(self.latency_s, 6) if self.latency_s is not None else None,
            "attempts": self.attempts,
        }


class MessageService:
    """Отправка и приём прикладных сообщений."""

    def __init__(self, node: Node) -> None:
        self.node = node
        self.manager = node.tunnels
        self.manager.on_app_message = self._on_incoming
        self._seen: ReplayGuard = ReplayGuard(capacity=node.config.replay_cache_size, ttl=3600.0)
        self._history: deque[MessageRecord] = deque(maxlen=node.config.history_size)
        self.sent = 0
        self.received = 0
        self.duplicates = 0
        self.rejected = 0

    # -------------------------------------------------------------- отправка

    async def send_text(
        self,
        destination_node_id: bytes,
        text: str,
        *,
        timeout: float | None = None,
    ) -> MessageRecord:
        """Отправить текст получателю через туннель и дождаться подтверждения."""
        encoded = text.encode("utf-8")
        if len(encoded) > self.node.config.max_message_bytes:
            raise TunnelError(
                f"message is {len(encoded)} bytes, limit is {self.node.config.max_message_bytes}"
            )
        if destination_node_id == self.node.node_id:
            raise TunnelError("cannot send a message to itself")

        destination = await self.node.resolve_contact(destination_node_id)
        message_id = secrets.token_bytes(16)
        payload = {
            "kind": KIND_MESSAGE,
            "message_id": message_id,
            "from": self.node.node_id,
            "text": text,
            "sent_at": time.time(),
        }
        started = time.perf_counter()
        tunnel, reply = await self.manager.send_message(destination, payload, timeout=timeout)
        latency = time.perf_counter() - started

        if reply.get("kind") != KIND_ACK or reply.get("message_id") != message_id:
            raise TunnelError("invalid delivery acknowledgement")
        status = str(reply.get("status", "unknown"))
        record = MessageRecord(
            message_id=message_id,
            direction="out",
            peer=destination.short_id,
            text=text,
            status=status,
            at=time.time(),
            tunnel_id=tunnel.tunnel_id.hex(),
            hops=tunnel.hops(self.node.node_id),
            latency_s=latency,
            attempts=tunnel.attempts,
        )
        self._history.append(record)
        self.sent += 1
        self.node.metrics.emit(
            "app.sent",
            message_id=message_id.hex(),
            to=destination.short_id,
            status=status,
            latency_s=round(latency, 6),
            hops=record.hops,
            relays=len(tunnel.relays),
        )
        return record

    # ----------------------------------------------------------------- приём

    async def _on_incoming(
        self, message: dict[str, Any], session: E2ESession, peer_id: bytes | None
    ) -> None:
        if message.get("kind") != KIND_MESSAGE:
            return
        message_id = message.get("message_id")
        sender = message.get("from")
        if not isinstance(message_id, bytes) or len(message_id) != 16:
            self.rejected += 1
            return
        if not isinstance(sender, bytes):
            sender = peer_id
        if sender is None:
            self.rejected += 1
            return
        # Отправитель подтверждён сертификатом e2e-сессии, а не полем сообщения.
        if peer_id is not None and sender != peer_id:
            self.rejected += 1
            self.node.metrics.emit("app.rejected", reason="sender mismatch")
            await session.send(
                {"kind": KIND_ACK, "message_id": message_id, "status": "rejected"}
            )
            return

        fresh = self._seen.accept(sender, message_id)
        text = message.get("text")
        if not isinstance(text, str):
            text = ""
        if not fresh:
            self.duplicates += 1
            self.node.metrics.emit(
                "app.duplicate", message_id=message_id.hex(), peer=sender.hex()[:12]
            )
            await session.send(
                {"kind": KIND_ACK, "message_id": message_id, "status": "duplicate"}
            )
            return

        record = MessageRecord(
            message_id=message_id,
            direction="in",
            peer=sender.hex()[:12],
            text=text,
            status="delivered",
            at=time.time(),
        )
        self._history.append(record)
        self.received += 1
        self.node.metrics.emit(
            "app.received", message_id=message_id.hex(), peer=sender.hex()[:12], size=len(text)
        )
        await session.send(
            {
                "kind": KIND_ACK,
                "message_id": message_id,
                "status": "delivered",
                "received_at": time.time(),
            }
        )

    # -------------------------------------------------------------- история

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        items = list(self._history)[-limit:]
        return [record.to_dict() for record in items]

    def stats(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "received": self.received,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "dedup": self._seen.stats(),
            "history_size": len(self._history),
        }
