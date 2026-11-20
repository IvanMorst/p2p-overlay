"""Тесты инфраструктуры сертификатов и проверки удалённой стороны."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from overlay.errors import IdentityError
from overlay.identity import Identity
from overlay.security.pki import (
    CA_CERT_FILE,
    CA_KEY_FILE,
    certificate_matches_identity,
    create_ca,
    issue_node_certificate,
    load_ca_certificate,
)
from overlay.security.trust import CertificateError, verify_peer_certificate


@pytest.fixture
def ca(tmp_path: Path):
    return create_ca(tmp_path / "pki")


def test_ca_creation_is_idempotent(tmp_path: Path) -> None:
    first = create_ca(tmp_path / "pki")
    second = create_ca(tmp_path / "pki")
    assert first.cert_path == second.cert_path
    assert first.cert_path.name == CA_CERT_FILE
    assert first.key_path.name == CA_KEY_FILE
    cert = load_ca_certificate(first.cert_path)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True


def test_node_certificate_is_issued_by_ca_and_matches_identity(ca, tmp_path: Path) -> None:
    identity = Identity.generate()
    bundle = issue_node_certificate(identity, ca.cert_path, ca.key_path, tmp_path / "node")
    assert certificate_matches_identity(bundle.cert_path, identity)

    cert = x509.load_pem_x509_certificate(bundle.cert_path.read_bytes())
    ca_cert = load_ca_certificate(ca.cert_path)
    assert cert.issuer == ca_cert.subject

    der = cert.public_bytes(serialization.Encoding.DER)
    peer = verify_peer_certificate(der, node_id_bits=256)
    assert peer.node_id == identity.node_id
    assert peer.public_key_der == identity.public_key_der


def test_trust_rejects_expected_node_id_mismatch(ca, tmp_path: Path) -> None:
    identity = Identity.generate()
    bundle = issue_node_certificate(identity, ca.cert_path, ca.key_path, tmp_path / "node")
    der = x509.load_pem_x509_certificate(bundle.cert_path.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )
    other = Identity.generate()
    with pytest.raises(CertificateError):
        verify_peer_certificate(der, node_id_bits=256, expected_node_id=other.node_id)


def test_trust_rejects_expired_certificate(ca, tmp_path: Path) -> None:
    identity = Identity.generate()
    bundle = issue_node_certificate(
        identity, ca.cert_path, ca.key_path, tmp_path / "node", lifetime_days=1
    )
    der = x509.load_pem_x509_certificate(bundle.cert_path.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )
    future = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=5)
    with pytest.raises(CertificateError):
        verify_peer_certificate(der, node_id_bits=256, now=future)


def test_trust_rejects_missing_certificate() -> None:
    with pytest.raises(CertificateError):
        verify_peer_certificate(b"", node_id_bits=256)


def test_trust_rejects_garbage() -> None:
    with pytest.raises(CertificateError):
        verify_peer_certificate(b"\x30\x02\x00\x00", node_id_bits=256)


def test_certificate_of_other_identity_is_detected(ca, tmp_path: Path) -> None:
    first = Identity.generate()
    second = Identity.generate()
    bundle = issue_node_certificate(first, ca.cert_path, ca.key_path, tmp_path / "node")
    assert not certificate_matches_identity(bundle.cert_path, second)


def test_missing_ca_key_raises(tmp_path: Path) -> None:
    identity = Identity.generate()
    with pytest.raises(IdentityError):
        issue_node_certificate(
            identity,
            tmp_path / "missing-ca.pem",
            tmp_path / "missing-key.pem",
            tmp_path / "node",
        )

def test_certificate_of_other_ca_is_rejected(tmp_path: Path) -> None:
    """Сертификат, выпущенный другим CA стенда, не принимается."""
    ca_first = create_ca(tmp_path / "pki-first")
    ca_second = create_ca(tmp_path / "pki-second")
    identity = Identity.generate()
    bundle = issue_node_certificate(
        identity, ca_first.cert_path, ca_first.key_path, tmp_path / "node"
    )
    assert certificate_matches_identity(bundle.cert_path, identity, ca_first.cert_path)
    assert not certificate_matches_identity(bundle.cert_path, identity, ca_second.cert_path)
