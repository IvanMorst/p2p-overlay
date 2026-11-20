"""Тесты контакта DHT: проверка ключа, адреса и сериализации."""

from __future__ import annotations

import pytest

from overlay.dht.contact import Contact
from overlay.errors import RoutingError
from overlay.identity import Identity


def _make(identity: Identity | None = None, **kwargs: object) -> Contact:
    identity = identity or Identity.generate()
    params = {
        "node_id": identity.node_id,
        "public_key_der": identity.public_key_der,
        "host": "127.0.0.1",
        "port": 7000,
    }
    params.update(kwargs)  # type: ignore[arg-type]
    return Contact(**params)  # type: ignore[arg-type]


def test_contact_accepts_matching_key() -> None:
    contact = _make()
    assert contact.node_id
    assert contact.address == "127.0.0.1:7000"


def test_contact_rejects_substituted_key() -> None:
    identity = Identity.generate()
    other = Identity.generate()
    with pytest.raises(RoutingError):
        _make(identity, public_key_der=other.public_key_der)


def test_contact_rejects_bad_address() -> None:
    with pytest.raises(RoutingError):
        _make(host="bad host!")
    with pytest.raises(RoutingError):
        _make(port=0)
    with pytest.raises(RoutingError):
        _make(port=70_000)


def test_contact_cbor_roundtrip() -> None:
    contact = _make()
    restored = Contact.from_cbor(contact.to_cbor())
    assert restored.node_id == contact.node_id
    assert restored.host == contact.host
    assert restored.port == contact.port
    assert restored.public_key_der == contact.public_key_der


def test_contact_from_cbor_rejects_forged_identity() -> None:
    contact = _make()
    forged = dict(contact.to_cbor())
    forged["id"] = Identity.generate().node_id
    with pytest.raises(RoutingError):
        Contact.from_cbor(forged)


def test_contact_from_cbor_rejects_missing_fields() -> None:
    with pytest.raises(RoutingError):
        Contact.from_cbor({"id": b"\x00" * 32})
    with pytest.raises(RoutingError):
        Contact.from_cbor("not a map")


def test_contact_touch_and_failure_are_immutable_updates() -> None:
    contact = _make()
    touched = contact.touch(123.0)
    assert contact.last_seen == 0.0
    assert touched.last_seen == 123.0
    failed = touched.mark_failure()
    assert failed.failures == 1
    assert touched.failures == 0


def test_ipv6_address_formatting() -> None:
    contact = _make(host="::1")
    assert contact.address == "[::1]:7000"
