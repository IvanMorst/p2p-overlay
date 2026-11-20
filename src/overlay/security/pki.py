"""Инфраструктура открытых ключей стенда.

Стенд использует собственный корневой сертификат (CA). Каждый узел получает
сертификат, подписанный этим CA, и предъявляет его при TLS-рукопожатии.
Ключ сертификата — долговременный identity-ключ Ed25519, поэтому ``NodeID``
вычисляется из того же открытого ключа, что и в сертификате.

Почему не самоподписанные сертификаты узлов: TLS-клиент обязан проверить
цепочку, а цепочку из самоподписанного сертификата проверить не по чему.
Самоподписанный сертификат можно «принять», только отключив проверку, что
прямо запрещено ТЗ. Отдельный CA стенда даёт настоящую проверку цепочки,
а привязка ключа сертификата к ``NodeID`` даёт аутентификацию узла.

Ограничение модели: ключ CA в эталонном стенде доступен провижининг-скрипту
(``overlay pki init``) и не передаётся узлам, которым сертификат уже выдан.
Даже при компрометации ключа CA подделать чужой ``NodeID`` нельзя: для этого
нужен закрытый ключ владельца, а ``NodeID`` считается из открытого ключа, а не
из имени в сертификате.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..errors import IdentityError
from ..identity import Identity

log = logging.getLogger(__name__)

CA_CERT_FILE = "ca.pem"
CA_KEY_FILE = "ca-key.pem"
NODE_CERT_FILE = "tls-cert.pem"
NODE_KEY_FILE = "tls-key.pem"
CA_COMMON_NAME = "overlay-stand-ca"
CA_LIFETIME_DAYS = 3650


@dataclass(frozen=True, slots=True)
class CertificateBundle:
    """Пути к сертификату узла и его закрытому ключу."""

    cert_path: Path
    key_path: Path

    def exists(self) -> bool:
        return self.cert_path.exists() and self.key_path.exists()


# --------------------------------------------------------------------- CA


def create_ca(directory: Path, *, lifetime_days: int = CA_LIFETIME_DAYS) -> CertificateBundle:
    """Создать корневой сертификат стенда и его ключ."""
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / CA_CERT_FILE
    key_path = directory / CA_KEY_FILE
    if cert_path.exists() and key_path.exists():
        log.info("CA already exists in %s", directory)
        return CertificateBundle(cert_path, key_path)

    key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, None)
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _restrict(key_path)
    log.info("created stand CA in %s", directory)
    return CertificateBundle(cert_path, key_path)


def load_ca_certificate(path: Path) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(Path(path).read_bytes())
    except Exception as e:
        raise IdentityError(f"cannot load CA certificate {path}: {e}") from e


# ------------------------------------------------------------------- узлы


def issue_node_certificate(
    identity: Identity,
    ca_cert_path: Path,
    ca_key_path: Path,
    out_dir: Path,
    *,
    lifetime_days: int = 365,
) -> CertificateBundle:
    """Выпустить сертификат узла, подписанный CA стенда."""
    ca_cert = load_ca_certificate(ca_cert_path)
    ca_key = _load_private_key(ca_key_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    cert_path = out_dir / NODE_CERT_FILE
    key_path = out_dir / NODE_KEY_FILE

    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"overlay-node-{identity.node_id.hex()[:32]}")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(identity.public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, None)
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(identity.private_key_pem)
    _restrict(key_path)
    return CertificateBundle(cert_path, key_path)


def certificate_matches_identity(cert_path: Path, identity: Identity) -> bool:
    """Проверить, что сертификат выпущен для текущего identity-ключа."""
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    except Exception:
        return False
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if spki != identity.public_key_der:
        return False
    now = datetime.datetime.now(datetime.UTC)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except Exception as e:
        raise IdentityError(f"cannot load private key {path}: {e}") from e
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise IdentityError("CA key must be Ed25519")
    return key


def _restrict(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - платформенная особенность
        pass
