"""Тесты модели маршрута туннеля."""

from __future__ import annotations

import pytest

from overlay.dht.contact import Contact
from overlay.errors import TunnelError
from overlay.identity import Identity
from overlay.tunnel.route import Route, RouteHop, validate_route


def _hop() -> RouteHop:
    identity = Identity.generate()
    return RouteHop(
        node_id=identity.node_id,
        public_key_der=identity.public_key_der,
        host="127.0.0.1",
        port=7000,
    )


def _route(length: int) -> Route:
    return Route(tuple(_hop() for _ in range(length)))


def test_hop_roundtrip() -> None:
    hop = _hop()
    restored = RouteHop.from_cbor(hop.to_cbor())
    assert restored == hop
    assert restored.short_id == hop.node_id[:6].hex()


def test_hop_from_contact() -> None:
    identity = Identity.generate()
    contact = Contact(
        node_id=identity.node_id,
        public_key_der=identity.public_key_der,
        host="127.0.0.1",
        port=7100,
    )
    hop = RouteHop.from_contact(contact)
    assert hop.to_contact() == contact


def test_hop_rejects_bad_address() -> None:
    identity = Identity.generate()
    with pytest.raises(TunnelError):
        RouteHop(
            node_id=identity.node_id,
            public_key_der=identity.public_key_der,
            host="bad host",
            port=7000,
        )


def test_route_accepts_valid_chain() -> None:
    route = _route(3)
    validate_route(route, local_id=bytes(32), max_hops=5, min_relays=2)
    assert route.length == 3
    assert len(route.relays) == 2
    assert route.destination == route.hops[-1]


def test_route_rejects_too_few_relays() -> None:
    with pytest.raises(TunnelError):
        validate_route(_route(2), local_id=bytes(32), max_hops=5, min_relays=2)


def test_route_rejects_too_many_hops() -> None:
    with pytest.raises(TunnelError):
        validate_route(_route(6), local_id=bytes(32), max_hops=5, min_relays=2)


def test_route_rejects_duplicates() -> None:
    hop = _hop()
    route = Route((hop, hop))
    with pytest.raises(TunnelError):
        validate_route(route, local_id=bytes(32), max_hops=5, min_relays=1)


def test_route_rejects_initiator() -> None:
    route = _route(3)
    with pytest.raises(TunnelError):
        validate_route(
            route,
            local_id=route.hops[0].node_id,
            max_hops=5,
            min_relays=2,
            initiator_id=route.hops[0].node_id,
        )


def test_route_rejects_foreign_identifier_length() -> None:
    short = Identity.generate(node_id_bits=64)
    hop = RouteHop(
        node_id=short.node_id,
        public_key_der=short.public_key_der,
        host="127.0.0.1",
        port=7000,
    )
    route = Route((hop, _hop()))
    with pytest.raises(TunnelError):
        validate_route(route, local_id=bytes(32), max_hops=5, min_relays=1)


def test_route_cbor_roundtrip() -> None:
    route = _route(3)
    restored = Route.from_cbor(route.to_cbor())
    assert restored.hops == route.hops


def test_route_from_cbor_rejects_empty() -> None:
    with pytest.raises(TunnelError):
        Route.from_cbor([])
    with pytest.raises(TunnelError):
        Route.from_cbor("not a route")


def test_path_includes_initiator() -> None:
    route = _route(3)
    initiator = Identity.generate()
    path = route.path(initiator.node_id)
    assert path[0] == initiator.node_id[:6].hex()
    assert len(path) == 4
