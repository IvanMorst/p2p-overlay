"""Клиентская сторона DHT-RPC: PING, FIND_NODE, STORE, FIND_VALUE.

Каждый запрос уходит в отдельном кадре с уникальным ``request_id`` и
коррелируется транспортом. Ошибки одного узла не прерывают остальные запросы:
вызывающая сторона получает исключение и решает, исключать ли контакт.
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import NodeConfig
from ..errors import ProtocolError, RemoteError, RoutingError, TimeoutExpired
from ..metrics import EventRecorder
from ..peers import PeerManager
from ..transport import codec
from ..transport.frame import Frame, MsgType
from .contact import Contact

log = logging.getLogger(__name__)


class DhtRpc:
    """Инициатор DHT-RPC поверх защищённых соединений."""

    def __init__(
        self,
        peers: PeerManager,
        config: NodeConfig,
        *,
        metrics: EventRecorder | None = None,
    ) -> None:
        self._peers = peers
        self._config = config
        self._metrics = metrics
        self.rpc_count = 0
        self.timeout_count = 0
        self.error_count = 0

    # ------------------------------------------------------------------ PING

    async def ping(self, contact: Contact) -> bool:
        """Проверить доступность контакта (используется при вытеснении LRU)."""
        try:
            conn = await self._peers.dial(contact)
            self.rpc_count += 1
            await conn.request(
                MsgType.PING,
                payload=codec.encode_payload({}),
                timeout=self._config.request_timeout_seconds,
                expected_type=MsgType.PONG,
            )
            return True
        except TimeoutExpired:
            self.timeout_count += 1
            return False
        except (RemoteError, ProtocolError, OSError) as e:
            self.error_count += 1
            log.debug("ping %s failed: %s", contact.short_id, e)
            return False

    # ------------------------------------------------------------- FIND_NODE

    async def find_node(self, contact: Contact, target: bytes) -> list[Contact]:
        """Запросить до ``k`` контактов, близких к ``target``."""
        payload = codec.encode_payload({"target": target, "count": self._config.k_bucket_size})
        conn = await self._peers.dial(contact)
        self.rpc_count += 1
        try:
            reply = await conn.request(
                MsgType.FIND_NODE_REQUEST,
                payload=payload,
                timeout=self._config.request_timeout_seconds,
                expected_type=MsgType.FIND_NODE_RESPONSE,
            )
        except TimeoutExpired:
            self.timeout_count += 1
            raise
        except RemoteError:
            self.error_count += 1
            raise
        return self._parse_contacts(reply, source=contact)

    def _parse_contacts(self, reply: Frame, *, source: Contact) -> list[Contact]:
        obj = codec.decode_mapping(reply.payload)
        raw = obj.get("contacts", [])
        if not isinstance(raw, list):
            raise ProtocolError("contacts field must be a list")
        contacts: list[Contact] = []
        for item in raw[: self._config.k_bucket_size]:
            try:
                candidate = Contact.from_cbor(item)
            except (RoutingError, KeyError, TypeError) as e:
                log.debug("dropping invalid contact from %s: %s", source.short_id, e)
                if self._metrics is not None:
                    self._metrics.emit("dht.contact_rejected", peer=source.short_id, reason=str(e))
                continue
            if len(candidate.node_id) != self._config.node_id_bytes:
                continue
            contacts.append(candidate)
        return contacts

    # ----------------------------------------------------------------- STORE

    async def store(self, contact: Contact, key: bytes, record: dict[str, Any]) -> bool:
        """Отправить запись на хранение; вернуть подтверждение хранителя."""
        payload = codec.encode_payload({"key": key, "record": record})
        conn = await self._peers.dial(contact)
        self.rpc_count += 1
        try:
            reply = await conn.request(
                MsgType.STORE_REQUEST,
                payload=payload,
                timeout=self._config.request_timeout_seconds,
                expected_type=MsgType.STORE_RESPONSE,
            )
        except TimeoutExpired:
            self.timeout_count += 1
            raise
        obj = codec.decode_mapping(reply.payload)
        return bool(obj.get("stored", False))

    # ------------------------------------------------------------ FIND_VALUE

    async def find_value(
        self, contact: Contact, key: bytes
    ) -> tuple[dict[str, Any] | None, list[Contact]]:
        """Запросить значение; при отсутствии получить близкие контакты."""
        payload = codec.encode_payload({"key": key})
        conn = await self._peers.dial(contact)
        self.rpc_count += 1
        try:
            reply = await conn.request(
                MsgType.FIND_VALUE_REQUEST,
                payload=payload,
                timeout=self._config.request_timeout_seconds,
                expected_type=MsgType.FIND_VALUE_RESPONSE,
            )
        except TimeoutExpired:
            self.timeout_count += 1
            raise
        except RemoteError:
            self.error_count += 1
            raise
        obj = codec.decode_mapping(reply.payload)
        value = obj.get("value")
        if isinstance(value, dict):
            return value, []
        return None, self._parse_contacts(reply, source=contact)

    # ----------------------------------------------------------------- stats

    def stats(self) -> dict[str, int]:
        return {
            "rpc": self.rpc_count,
            "timeouts": self.timeout_count,
            "errors": self.error_count,
        }
