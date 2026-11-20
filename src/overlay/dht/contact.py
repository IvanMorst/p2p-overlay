"""Контакт DHT: идентификатор, ключ, адрес и время последнего наблюдения."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any

from ..addressing import is_valid_host, is_valid_port
from ..errors import RoutingError
from ..identity import compute_node_id, verify_node_id


@dataclass(frozen=True, slots=True)
class Contact:
    """Валидированный контакт участника оверлея."""

    node_id: bytes
    host: str
    port: int
    public_key_der: bytes
    last_seen: float = field(default=0.0, compare=False)
    failures: int = field(default=0, compare=False)

    def __post_init__(self) -> None:
        if not 1 <= len(self.node_id) <= 32:
            raise RoutingError(f"invalid node_id length: {len(self.node_id)}")
        if not is_valid_host(self.host):
            raise RoutingError(f"invalid host: {self.host!r}")
        if not is_valid_port(self.port):
            raise RoutingError(f"invalid port: {self.port}")
        if not verify_node_id(self.node_id, self.public_key_der, len(self.node_id) * 8):
            raise RoutingError("NodeID does not match the presented public key")

    # ------------------------------------------------------------ conversion

    def to_cbor(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "host": self.host,
            "port": self.port,
            "key": self.public_key_der,
        }

    @classmethod
    def from_cbor(cls, obj: Any) -> Contact:
        if not isinstance(obj, dict):
            raise RoutingError("contact must be a map")
        try:
            node_id = obj["id"]
            host = obj["host"]
            port = obj["port"]
            key = obj["key"]
        except KeyError as e:
            raise RoutingError(f"contact misses field {e}") from e
        if not isinstance(node_id, bytes) or not isinstance(key, bytes):
            raise RoutingError("contact id/key must be byte strings")
        if not isinstance(host, str) or not isinstance(port, int):
            raise RoutingError("contact host/port must be str/int")
        return cls(node_id=node_id, host=host, port=port, public_key_der=key)

    @classmethod
    def from_identity(
        cls, *, node_id: bytes, public_key_der: bytes, host: str, port: int
    ) -> Contact:
        return cls(node_id=node_id, public_key_der=public_key_der, host=host, port=port)

    # ------------------------------------------------------------- accessors

    @property
    def short_id(self) -> str:
        return self.node_id[:6].hex()

    @property
    def address(self) -> str:
        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    def with_node_id(self, node_id: bytes) -> Contact:
        return replace(self, node_id=node_id)

    def touch(self, now: float | None = None) -> Contact:
        return replace(self, last_seen=now if now is not None else time.monotonic(), failures=0)

    def mark_failure(self) -> Contact:
        return replace(self, failures=self.failures + 1)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id.hex(),
            "address": self.address,
            "last_seen": round(self.last_seen, 3),
            "failures": self.failures,
        }


def node_id_prefix(public_key_der: bytes, node_id_bits: int) -> bytes:
    return compute_node_id(public_key_der, node_id_bits)
