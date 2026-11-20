"""Тесты идентичности: формула NodeID, тест-вектор, сохранение, подпись."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from overlay.errors import IdentityError
from overlay.identity import Identity, compute_node_id, verify_node_id

# Тест-вектор: закрытый ключ из байтов 0x00..0x1f и его производные.
VECTOR_PRIVATE = bytes(range(32))
VECTOR_SPKI_HEX = (
    "302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
)
VECTOR_NODE_ID_HEX = "a050837d85070582ccf7394b0988847cc312cb88259b894899f6f239cf1791a5"
VECTOR_SIGNATURE_HEX = (
    "0b400ba3a6a64cb07ba5505dba519f2b365596747c0932eb03b57badf90cc843"
    "5f8b284edd94ed756a7b28ae34358ab92901c9abc58b9ea1bb95d4d418b88306"
)


def _vector_identity() -> Identity:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(VECTOR_PRIVATE)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return Identity.from_private_pem(pem)


def test_node_id_matches_sha256_of_spki() -> None:
    identity = Identity.generate()
    expected = hashlib.sha256(identity.public_key_der).digest()
    assert identity.node_id == expected
    assert len(identity.node_id) == 32


def test_identity_test_vector() -> None:
    identity = _vector_identity()
    assert identity.public_key_der.hex() == VECTOR_SPKI_HEX
    assert identity.node_id.hex() == VECTOR_NODE_ID_HEX


def test_node_id_truncation_follows_configured_bits() -> None:
    identity = Identity.generate()
    truncated = compute_node_id(identity.public_key_der, 160)
    assert truncated == identity.node_id[:20]
    assert verify_node_id(truncated, identity.public_key_der, 160)
    assert not verify_node_id(truncated, identity.public_key_der, 256)


def test_signature_verification() -> None:
    identity = Identity.generate()
    data = b"canonical-record"
    signature = identity.sign(data)
    assert Identity.verify_signature(identity.public_key_der, signature, data)
    assert not Identity.verify_signature(identity.public_key_der, signature, data + b"!")
    # Подмена открытого ключа делает подпись недействительной.
    other = Identity.generate()
    assert not Identity.verify_signature(other.public_key_der, signature, data)


def test_signature_test_vector() -> None:
    identity = _vector_identity()
    assert identity.sign(b"overlay-test-vector").hex() == VECTOR_SIGNATURE_HEX


def test_identity_persists_across_restart(tmp_path: Path) -> None:
    first = Identity.load_or_create(tmp_path, 256)
    second = Identity.load_or_create(tmp_path, 256)
    assert first.node_id == second.node_id
    assert first.public_key_der == second.public_key_der


def test_identity_state_dir_does_not_leak_private_key(tmp_path: Path) -> None:
    identity = Identity.load_or_create(tmp_path, 256)
    pem = (tmp_path / "ed25519-private.pem").read_text(encoding="utf-8")
    assert "PRIVATE KEY" in pem
    metadata = (tmp_path / "identity.json").read_text(encoding="utf-8")
    assert identity.node_id.hex() in metadata
    # В метаданных нет тела закрытого ключа в любом представлении.
    body = base64.b64encode(VECTOR_PRIVATE).decode()
    assert body not in metadata
    assert identity.private_key_pem.decode().strip().splitlines()[-2] not in metadata
    assert base64.b64encode(identity.public_key_der).decode() in metadata


def test_identity_rejects_bits_change(tmp_path: Path) -> None:
    Identity.load_or_create(tmp_path, 256)
    with pytest.raises(IdentityError):
        Identity.load_or_create(tmp_path, 160)


def test_node_id_bits_validation() -> None:
    identity = Identity.generate()
    with pytest.raises(IdentityError):
        compute_node_id(identity.public_key_der, 100)
    with pytest.raises(IdentityError):
        compute_node_id(identity.public_key_der, 264)
