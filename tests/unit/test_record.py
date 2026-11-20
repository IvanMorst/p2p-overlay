"""Тесты подписанной записи DHT: формат, подпись, TTL, адреса."""

from __future__ import annotations

import hashlib
import time
from dataclasses import replace

import pytest

from overlay.config import NodeConfig
from overlay.dht.record import (
    Address,
    BadAddress,
    BadRecordSignature,
    ExpiredRecord,
    MalformedRecord,
    NodeRecord,
    NotYetValidRecord,
    RecordIdentityMismatch,
    RecordTooLarge,
    parse_record,
    record_key_for_node,
    validate_record,
)
from overlay.identity import Identity

CONFIG = NodeConfig()  # значения по умолчанию: TTL 180, лимит записи 4096


def _record(identity: Identity | None = None, **kwargs: object) -> NodeRecord:
    identity = identity or Identity.generate()
    params = {
        "sequence_number": 1,
        "ttl_seconds": CONFIG.record_ttl_seconds,
    }
    params.update(kwargs)  # type: ignore[arg-type]
    return NodeRecord.create(
        identity,
        [Address("127.0.0.1", 7000)],
        **params,  # type: ignore[arg-type]
    )


def test_record_roundtrip_and_validation() -> None:
    record = _record()
    validate_record(record, CONFIG)
    restored = parse_record(record.to_cbor())
    assert restored == record
    assert restored.record_key == record.record_key


def test_record_key_is_sha256_of_prefixed_node_id() -> None:
    record = _record()
    expected = hashlib.sha256(b"node:" + record.node_id).digest()
    assert record.record_key == expected
    assert record_key_for_node(record.node_id) == expected


def test_record_signature_covers_all_fields() -> None:
    record = _record()
    tampered_variants = [
        replace(record, addresses=(Address("127.0.0.1", 7001),)),
        replace(record, sequence_number=record.sequence_number + 1),
        replace(record, issued_at=record.issued_at + 1),
        replace(record, expires_at=record.expires_at + 1),
    ]
    for tampered in tampered_variants:
        with pytest.raises(BadRecordSignature):
            validate_record(tampered, CONFIG)


def test_record_rejects_foreign_signature() -> None:
    record = _record()
    other = Identity.generate()
    forged = NodeRecord(
        node_id=record.node_id,
        identity_public_key=record.identity_public_key,
        addresses=record.addresses,
        sequence_number=record.sequence_number,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        signature=other.sign(record.signed_payload()),
    )
    with pytest.raises(BadRecordSignature):
        validate_record(forged, CONFIG)


def test_record_rejects_substituted_identity_key() -> None:
    identity = Identity.generate()
    record = _record(identity)
    other = Identity.generate()
    forged = NodeRecord(
        node_id=record.node_id,
        identity_public_key=other.public_key_der,
        addresses=record.addresses,
        sequence_number=record.sequence_number,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        signature=record.signature,
    )
    with pytest.raises(RecordIdentityMismatch):
        validate_record(forged, CONFIG)


def test_record_rejects_expired() -> None:
    record = _record()
    with pytest.raises(ExpiredRecord):
        validate_record(record, CONFIG, now=record.expires_at + 1)


def test_record_rejects_future_issue_time() -> None:
    record = _record()
    with pytest.raises(NotYetValidRecord):
        validate_record(record, CONFIG, now=record.issued_at - 3600)


def test_record_rejects_inverted_interval() -> None:
    """Запись с expires_at <= issued_at отклоняется даже при верной подписи."""
    identity = Identity.generate()
    base = _record(identity)
    unsigned = NodeRecord(
        node_id=base.node_id,
        identity_public_key=base.identity_public_key,
        addresses=base.addresses,
        sequence_number=1,
        issued_at=base.expires_at,
        expires_at=base.expires_at,
        signature=b"",
    )
    broken = replace(unsigned, signature=identity.sign(unsigned.signed_payload()))
    with pytest.raises(NotYetValidRecord):
        validate_record(broken, CONFIG)


def test_record_rejects_too_many_addresses() -> None:
    identity = Identity.generate()
    addresses = [Address("127.0.0.1", 7000 + i) for i in range(CONFIG.max_addresses + 1)]
    record = NodeRecord.create(
        identity, addresses, sequence_number=1, ttl_seconds=CONFIG.record_ttl_seconds
    )
    with pytest.raises(BadAddress):
        validate_record(record, CONFIG)


def test_record_rejects_empty_addresses() -> None:
    with pytest.raises(BadAddress):
        _record_with_empty_addresses()


def _record_with_empty_addresses() -> NodeRecord:
    identity = Identity.generate()
    return NodeRecord.create(
        identity, [], sequence_number=1, ttl_seconds=CONFIG.record_ttl_seconds
    )


def test_record_rejects_invalid_address() -> None:
    with pytest.raises(BadAddress):
        Address("bad host!", 7000)
    with pytest.raises(BadAddress):
        Address("127.0.0.1", 0)


def test_record_rejects_oversized_payload() -> None:
    identity = Identity.generate()
    small = NodeConfig(max_record_bytes=64)
    record = NodeRecord.create(
        identity,
        [Address("127.0.0.1", 7000)],
        sequence_number=1,
        ttl_seconds=small.record_ttl_seconds,
    )
    with pytest.raises(RecordTooLarge):
        validate_record(record, small)


def test_record_rejects_ttl_above_network_limit() -> None:
    identity = Identity.generate()
    record = NodeRecord.create(
        identity,
        [Address("127.0.0.1", 7000)],
        sequence_number=1,
        ttl_seconds=CONFIG.record_ttl_seconds * 10,
    )
    with pytest.raises(NotYetValidRecord):
        validate_record(record, CONFIG)


def test_parse_record_rejects_malformed_input() -> None:
    with pytest.raises(MalformedRecord):
        parse_record("not a map")
    with pytest.raises(MalformedRecord):
        parse_record({"node_id": b"\x00" * 32})
    record = _record()
    broken = dict(record.to_cbor())
    broken["sequence_number"] = -1
    with pytest.raises(MalformedRecord):
        parse_record(broken)


def test_record_ttl_and_expiry_helpers() -> None:
    record = _record(ttl_seconds=120)
    assert record.ttl_seconds == 120
    now = time.time()
    assert not record.is_expired(now)
    assert record.is_expired(record.expires_at + 1)
