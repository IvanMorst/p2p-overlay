"""Долговременная идентичность узла и производный NodeID.

Правила (раздел 9 ТЗ):

* при первом запуске создаётся пара ключей Ed25519 и сохраняется в
  индивидуальном каталоге состояния;
* ``NodeID = SHA-256(canonical_encode(identity_public_key))``, усечённый до
  ``node_id_bits`` бит (по умолчанию 256 — ровно формула ТЗ);
* ``canonical_encode`` открытого ключа — DER SubjectPublicKeyInfo (44 байта для
  Ed25519), канонический по построению;
* закрытый ключ не передаётся по сети и не коммитится в репозиторий.

Усечение разрядности управляется параметром ``NODE_ID_BITS`` (раздел 14 ТЗ):
оно позволяет исследовать заполнение k-bucket на малом числе узлов, не меняя
код. Значение по умолчанию 256 бит соответствует полной формуле.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .errors import IdentityError

log = logging.getLogger(__name__)

IDENTITY_STATE_FILE = "identity.json"
PRIVATE_KEY_FILE = "ed25519-private.pem"
PUBLIC_KEY_FILE = "ed25519-public.pem"


def canonical_public_key(public_key_der: bytes) -> bytes:
    """Каноническое представление открытого ключа для вычисления NodeID.

    Для Ed25519 это DER SubjectPublicKeyInfo: структура с фиксированным
    порядком полей, поэтому две реализации получают одинаковые байты.
    """
    return public_key_der


def compute_node_id(public_key_der: bytes, node_id_bits: int = 256) -> bytes:
    """``NodeID = SHA-256(canonical_encode(public_key))[:node_id_bits / 8]``."""
    if node_id_bits % 8 != 0 or not 8 <= node_id_bits <= 256:
        raise IdentityError(f"invalid node_id_bits: {node_id_bits}")
    digest = hashlib.sha256(canonical_public_key(public_key_der)).digest()
    return digest[: node_id_bits // 8]


def verify_node_id(node_id: bytes, public_key_der: bytes, node_id_bits: int = 256) -> bool:
    """Проверить, что NodeID действительно выведен из открытого ключа."""
    try:
        expected = compute_node_id(public_key_der, node_id_bits)
    except IdentityError:
        return False
    return expected == node_id


def load_public_key(public_key_der: bytes) -> ed25519.Ed25519PublicKey:
    try:
        key = serialization.load_der_public_key(public_key_der)
    except Exception as e:
        raise IdentityError(f"malformed public key: {e}") from e
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise IdentityError("public key must be Ed25519")
    return key


@dataclass(frozen=True, slots=True)
class Identity:
    """Долговременная идентичность узла."""

    node_id: bytes
    public_key_der: bytes
    _private_key: ed25519.Ed25519PrivateKey

    # ------------------------------------------------------------ constructors

    @classmethod
    def generate(cls, node_id_bits: int = 256) -> Identity:
        key = ed25519.Ed25519PrivateKey.generate()
        public_der = _public_der(key)
        return cls(
            node_id=compute_node_id(public_der, node_id_bits),
            public_key_der=public_der,
            _private_key=key,
        )

    @classmethod
    def load_or_create(cls, state_dir: Path, node_id_bits: int = 256) -> Identity:
        """Загрузить идентичность из каталога состояния либо создать новую.

        Повторный запуск с тем же ``NODE_STATE_DIR`` обязан дать тот же NodeID
        (требование E2-1).
        """
        state_dir = Path(state_dir)
        private_path = state_dir / PRIVATE_KEY_FILE
        meta_path = state_dir / IDENTITY_STATE_FILE
        if private_path.exists():
            return cls._load(state_dir, node_id_bits)
        return cls._create(state_dir, node_id_bits, private_path, meta_path)

    @classmethod
    def from_private_pem(cls, pem: bytes, node_id_bits: int = 256) -> Identity:
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise IdentityError("private key must be Ed25519")
        public_der = _public_der(key)
        return cls(
            node_id=compute_node_id(public_der, node_id_bits),
            public_key_der=public_der,
            _private_key=key,
        )

    @classmethod
    def _load(cls, state_dir: Path, node_id_bits: int) -> Identity:
        pem = (state_dir / PRIVATE_KEY_FILE).read_bytes()
        identity = cls.from_private_pem(pem, node_id_bits)
        meta_path = state_dir / IDENTITY_STATE_FILE
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            recorded_bits = int(meta.get("node_id_bits", node_id_bits))
            if recorded_bits != node_id_bits:
                raise IdentityError(
                    "node_id_bits changed for an existing identity "
                    f"({recorded_bits} -> {node_id_bits}); use a fresh state dir"
                )
            recorded_id = bytes.fromhex(str(meta.get("node_id", "")))
            if recorded_id and recorded_id != identity.node_id:
                raise IdentityError("stored NodeID does not match the stored private key")
        else:
            identity._write_metadata(meta_path, node_id_bits)
        return identity

    @classmethod
    def _create(
        cls, state_dir: Path, node_id_bits: int, private_path: Path, meta_path: Path
    ) -> Identity:
        state_dir.mkdir(parents=True, exist_ok=True)
        identity = cls.generate(node_id_bits)
        pem = identity.private_key_pem
        private_path.write_bytes(pem)
        _restrict_permissions(private_path)
        (state_dir / PUBLIC_KEY_FILE).write_bytes(identity.public_key_pem)
        identity._write_metadata(meta_path, node_id_bits)
        log.info("generated new identity %s in %s", identity.short_id, state_dir)
        return identity

    def _write_metadata(self, path: Path, node_id_bits: int) -> None:
        payload = {
            "version": 1,
            "node_id": self.node_id.hex(),
            "node_id_bits": node_id_bits,
            "public_key_der_b64": base64.b64encode(self.public_key_der).decode("ascii"),
            "created_at": int(time.time()),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # ------------------------------------------------------------- properties

    @property
    def private_key(self) -> ed25519.Ed25519PrivateKey:
        return self._private_key

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._private_key.public_key()

    @property
    def short_id(self) -> str:
        return self.node_id[:6].hex()

    @property
    def node_id_hex(self) -> str:
        return self.node_id.hex()

    @property
    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # ---------------------------------------------------------------- actions

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def verify_signature(public_key_der: bytes, signature: bytes, data: bytes) -> bool:
        """Проверить подпись по предъявленному открытому ключу."""
        key = load_public_key(public_key_der)
        try:
            key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


def _public_der(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _restrict_permissions(path: Path) -> None:
    """Ограничить доступ к закрытому ключу (best effort на Windows)."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - платформенная особенность
        log.debug("could not restrict permissions on %s", path)
