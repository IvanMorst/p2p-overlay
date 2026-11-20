"""Проверка сертификата удалённой стороны и привязки ключа к NodeID.

TLS-слой проверяет цепочку до CA стенда. Приложение поверх этого проверяет:

* срок действия сертификата;
* что сертификат выдан именно тому узлу, чей ``NodeID`` ожидается: открытый
  ключ из сертификата повторно хешируется и сравнивается с заявленным;
* что ``NodeID`` совпадает с ожидаемым, если ожидание известно (из записи DHT
  или из таблицы маршрутизации).

Без последней проверки валидный сертификат любого участника стенда позволял бы
выдавать себя за другой узел.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from ..errors import IdentityError

log = logging.getLogger(__name__)


class CertificateError(IdentityError):
    """Сертификат удалённой стороны не подтверждает ожидаемую идентичность."""


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """Идентичность, подтверждённая сертификатом."""

    node_id: bytes
    public_key_der: bytes
    subject: str
    not_after: datetime.datetime

    @property
    def short_id(self) -> str:
        return self.node_id[:6].hex()

    def to_dict(self) -> dict[str, str]:
        return {
            "node_id": self.node_id.hex(),
            "subject": self.subject,
            "not_after": self.not_after.isoformat(),
        }


def compute_node_id_from_certificate(public_key_der: bytes, node_id_bits: int) -> bytes:
    digest = hashlib.sha256(public_key_der).digest()
    if node_id_bits % 8 != 0 or not 8 <= node_id_bits <= 256:
        raise CertificateError(f"invalid node_id_bits: {node_id_bits}")
    return digest[: node_id_bits // 8]


def verify_peer_certificate(
    der: bytes,
    *,
    node_id_bits: int,
    expected_node_id: bytes | None = None,
    now: datetime.datetime | None = None,
) -> PeerIdentity:
    """Проверить сертификат и вернуть подтверждённую идентичность."""
    if not der:
        raise CertificateError("peer did not present a certificate")

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        raise CertificateError(f"cannot parse peer certificate: {e}") from e

    stamp = now or datetime.datetime.now(datetime.UTC)
    if cert.not_valid_before_utc > stamp:
        raise CertificateError("peer certificate is not valid yet")
    if cert.not_valid_after_utc < stamp:
        raise CertificateError("peer certificate has expired")

    public_key_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    node_id = compute_node_id_from_certificate(public_key_der, node_id_bits)

    # Сертификат должен разрешать и клиентскую, и серверскую аутентификацию:
    # один и тот же узел выступает в обеих ролях.
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as e:
        raise CertificateError("peer certificate has no extended key usage") from e
    if not ({ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH} & set(eku)):
        raise CertificateError("peer certificate is not usable for TLS authentication")

    if expected_node_id is not None and node_id != expected_node_id:
        raise CertificateError(
            "certificate identity does not match the expected NodeID: "
            f"{node_id.hex()[:12]} != {expected_node_id.hex()[:12]}"
        )

    return PeerIdentity(
        node_id=node_id,
        public_key_der=public_key_der,
        subject=cert.subject.rfc4514_string(),
        not_after=cert.not_valid_after_utc,
    )
