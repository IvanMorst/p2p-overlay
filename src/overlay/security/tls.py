"""TLS 1.3 с взаимной аутентификацией.

Оба конца соединения предъявляют сертификат, подписанный CA стенда, и
проверяют цепочку до этого CA. Поверх проверки цепочки приложение проверяет
привязку открытого ключа сертификата к ``NodeID`` (``security.trust``) и
совпадение с ожидаемым ``NodeID``.

Свойства:

* `minimum_version = maximum_version = TLSv1_3` — TLS 1.2 и более ранние
  версии невозможны, откат версии не проходит;
* 0-RTT не используется: `asyncio` не открывает early data, `max_early_data`
  не задаётся, поэтому повтор ранних данных невозможен;
* проверка сертификата не отключается: `verify_mode = CERT_REQUIRED`,
  `check_hostname = False` только потому, что идентичность узла задаётся
  `NodeID`, а не DNS-именем;
* `session_id` соединения (16 случайных байт) используется для области
  действия учёта повторов.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Any

from ..config import NodeConfig
from ..errors import IdentityError
from ..identity import Identity
from ..transport.tcp import Connection
from .base import SecurityError
from .pki import (
    NODE_CERT_FILE,
    NODE_KEY_FILE,
    CertificateBundle,
    certificate_matches_identity,
    issue_node_certificate,
)
from .trust import PeerIdentity, verify_peer_certificate

log = logging.getLogger(__name__)


class TlsSecurity:
    """Слой защиты канала: TLS 1.3 + mTLS + привязка ключа к NodeID."""

    enabled = True

    def __init__(self, identity: Identity, config: NodeConfig) -> None:
        self._identity = identity
        self._config = config
        self._ca_path = _require_ca_path(config)
        self._bundle = self._ensure_certificate()
        self._server_context = self._build_context(ssl.PROTOCOL_TLS_SERVER)
        self._client_context = self._build_context(ssl.PROTOCOL_TLS_CLIENT)
        self._verified = 0
        self._rejected = 0

    # ------------------------------------------------------------- контексты

    def _build_context(self, protocol: int) -> ssl.SSLContext:
        context = ssl.SSLContext(protocol)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_verify_locations(cafile=str(self._ca_path))
        context.load_cert_chain(
            certfile=str(self._bundle.cert_path), keyfile=str(self._bundle.key_path)
        )
        return context

    def _ensure_certificate(self) -> CertificateBundle:
        cert_path = _resolve_path(self._config.cert_file) or (
            self._config.identity_dir / NODE_CERT_FILE
        )
        key_path = _resolve_path(self._config.key_file) or (
            self._config.identity_dir / NODE_KEY_FILE
        )
        bundle = CertificateBundle(Path(cert_path), Path(key_path))
        if bundle.exists() and certificate_matches_identity(
            bundle.cert_path, self._identity, self._ca_path
        ):
            return bundle
        ca_key = _resolve_path(self._config.ca_key)
        if ca_key is None or not ca_key.exists():
            raise IdentityError(
                "node certificate is missing or does not match the identity key; "
                "run `overlay pki issue --config <file>` with access to the CA key"
            )
        log.info("issuing node certificate for %s", self._identity.short_id)
        return issue_node_certificate(
            self._identity,
            self._ca_path,
            ca_key,
            Path(cert_path).parent,
            lifetime_days=self._config.certificate_lifetime_days,
        )

    # ------------------------------------------------------------ интерфейс

    def server_context(self) -> ssl.SSLContext | None:
        return self._server_context

    def client_context(self) -> ssl.SSLContext | None:
        return self._client_context

    def verify_peer(self, conn: Connection, expected_node_id: bytes | None) -> bytes:
        der = conn.peer_certificate_der
        try:
            peer = verify_peer_certificate(
                der or b"",
                node_id_bits=self._config.node_id_bits,
                expected_node_id=expected_node_id,
            )
        except IdentityError as e:
            self._rejected += 1
            raise SecurityError(str(e)) from e
        if conn.tls_version != "TLSv1.3":
            self._rejected += 1
            raise SecurityError(f"unexpected TLS version: {conn.tls_version}")
        self._verified += 1
        log.debug("verified peer %s via %s", peer.short_id, conn.tls_cipher)
        return peer.node_id

    def describe(self) -> dict[str, Any]:
        return {
            "mode": "tls13",
            "tls": True,
            "min_version": "TLSv1.3",
            "mutual": True,
            "verify_mode": "CERT_REQUIRED",
            "zero_rtt": False,
            "ca": str(self._ca_path),
            "certificate": str(self._bundle.cert_path),
            "verified_peers": self._verified,
            "rejected_peers": self._rejected,
        }

    def peer_identity(self, conn: Connection) -> PeerIdentity | None:
        der = conn.peer_certificate_der
        if not der:
            return None
        return verify_peer_certificate(der, node_id_bits=self._config.node_id_bits)


def _resolve_path(value: Any) -> Path | None:
    if value in (None, ""):
        return None
    return Path(str(value))


def _require_ca_path(config: NodeConfig) -> Path:
    path = _resolve_path(config.ca_cert)
    if path is None or not path.exists():
        raise IdentityError(
            "CA certificate is missing: set [security] ca_cert and run "
            "`overlay pki init --out <dir>` once for the stand"
        )
    return path
