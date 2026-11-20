"""Маршрут туннеля: последовательность различных узлов без петель.

Маршрут — это список переходов от первого ретранслятора до получателя.
Инициатор в список не входит: он источник, а не промежуточный узел.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..addressing import is_valid_host, is_valid_port
from ..dht.contact import Contact
from ..errors import TunnelError


@dataclass(frozen=True, slots=True)
class RouteHop:
    """Один узел маршрута: идентификатор, ключ и адрес."""

    node_id: bytes
    public_key_der: bytes
    host: str
    port: int

    def __post_init__(self) -> None:
        if not 1 <= len(self.node_id) <= 32:
            raise TunnelError("invalid hop node_id length")
        if not is_valid_host(self.host) or not is_valid_port(self.port):
            raise TunnelError(f"invalid hop address: {self.host}:{self.port}")

    @property
    def short_id(self) -> str:
        return self.node_id[:6].hex()

    def to_cbor(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "key": self.public_key_der,
            "host": self.host,
            "port": self.port,
        }

    @classmethod
    def from_cbor(cls, obj: Any) -> RouteHop:
        if not isinstance(obj, dict):
            raise TunnelError("route hop must be a map")
        try:
            node_id = obj["node_id"]
            key = obj["key"]
            host = obj["host"]
            port = obj["port"]
        except KeyError as e:
            raise TunnelError(f"route hop misses field {e}") from e
        if not isinstance(node_id, bytes) or not isinstance(key, bytes):
            raise TunnelError("route hop node_id/key must be byte strings")
        if not isinstance(host, str) or not isinstance(port, int):
            raise TunnelError("route hop host/port must be str/int")
        return cls(node_id=node_id, public_key_der=key, host=host, port=port)

    def to_contact(self) -> Contact:
        return Contact(
            node_id=self.node_id,
            public_key_der=self.public_key_der,
            host=self.host,
            port=self.port,
        )

    @classmethod
    def from_contact(cls, contact: Contact) -> RouteHop:
        return cls(
            node_id=contact.node_id,
            public_key_der=contact.public_key_der,
            host=contact.host,
            port=contact.port,
        )


@dataclass(frozen=True, slots=True)
class Route:
    """Проверенный маршрут туннеля."""

    hops: tuple[RouteHop, ...]

    @property
    def destination(self) -> RouteHop:
        return self.hops[-1]

    @property
    def relays(self) -> tuple[RouteHop, ...]:
        return self.hops[:-1]

    @property
    def length(self) -> int:
        return len(self.hops)

    def ids(self) -> list[bytes]:
        return [hop.node_id for hop in self.hops]

    def path(self, initiator: bytes) -> list[str]:
        return [initiator[:6].hex()] + [hop.short_id for hop in self.hops]

    def to_cbor(self) -> list[dict[str, Any]]:
        return [hop.to_cbor() for hop in self.hops]

    @classmethod
    def from_cbor(cls, obj: Any) -> Route:
        if not isinstance(obj, list) or not obj:
            raise TunnelError("route must be a non-empty list")
        return cls(tuple(RouteHop.from_cbor(item) for item in obj))


def validate_route(
    route: Route,
    *,
    local_id: bytes,
    max_hops: int,
    min_relays: int,
    initiator_id: bytes | None = None,
) -> None:
    """Проверить отсутствие петель, дубликатов и соблюдение лимитов.

    ``initiator_id`` передаётся только инициатором: маршрут не должен содержать
    его самого. Ретранслятор, наоборот, обязан присутствовать в маршруте, поэтому
    для него проверка не применяется.
    """
    ids = route.ids()
    if len(ids) < min_relays + 1:
        raise TunnelError(
            f"route has {len(ids) - 1} relays, at least {min_relays} required"
        )
    if len(ids) > max_hops:
        raise TunnelError(f"route length {len(ids)} exceeds max_hops {max_hops}")
    if len(set(ids)) != len(ids):
        raise TunnelError("route contains duplicate nodes (loop)")
    if initiator_id is not None and initiator_id in ids:
        raise TunnelError("route must not contain the initiator")
    for hop in route.hops:
        if len(hop.node_id) != len(local_id):
            raise TunnelError("route hop has a foreign identifier length")
