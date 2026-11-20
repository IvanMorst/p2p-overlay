"""Подписанная адресная запись DHT.

Структура (раздел 10.3 ТЗ)::

    NodeRecord {
        node_id,
        identity_public_key,
        addresses[],
        sequence_number,
        issued_at,
        expires_at,
        signature
    }

Каноническое представление — канонический CBOR словаря без поля ``signature``;
подпись Ed25519 вычисляется ровно по этим байтам. Ключ хранения записи::

    key = SHA-256("node:" || NodeID)

Проверки перед сохранением и использованием: связь ключа и ``NodeID``,
цифровая подпись, размер, формат адреса, срок действия, монотонность
``sequence_number`` (последняя проверка выполняется хранилищем, поскольку
требует сравнения с текущей версией).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from ..addressing import format_address, is_valid_host, is_valid_port
from ..config import NodeConfig
from ..errors import RecordError
from ..identity import Identity, load_public_key, verify_node_id
from ..transport import codec

NODE_KEY_PREFIX = b"node:"
CLOCK_SKEW_SECONDS = 60


class MalformedRecord(RecordError):
    """Запись не декодируется или не содержит обязательных полей."""


class RecordTooLarge(RecordError):
    """Закодированная запись превышает допустимый размер."""


class BadAddress(RecordError):
    """Адрес в записи некорректен."""


class BadRecordSignature(RecordError):
    """Подпись записи недействительна."""


class RecordIdentityMismatch(RecordError):
    """NodeID записи не выведен из её открытого ключа."""


class ExpiredRecord(RecordError):
    """Срок действия записи истёк."""


class NotYetValidRecord(RecordError):
    """Запись выдана в будущем либо имеет неверный интервал действия."""


class StaleRecord(RecordError):
    """Попытка отката: sequence_number меньше или равен сохранённому."""


@dataclass(frozen=True, slots=True)
class Address:
    host: str
    port: int

    def __post_init__(self) -> None:
        if not is_valid_host(self.host):
            raise BadAddress(f"invalid host: {self.host!r}")
        if not is_valid_port(self.port):
            raise BadAddress(f"invalid port: {self.port}")

    def to_cbor(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port}

    @classmethod
    def from_cbor(cls, obj: Any) -> Address:
        if not isinstance(obj, dict):
            raise BadAddress("address must be a map")
        host = obj.get("host")
        port = obj.get("port")
        if not isinstance(host, str) or not isinstance(port, int):
            raise BadAddress("address host/port must be str/int")
        return cls(host=host, port=port)

    def __str__(self) -> str:
        return format_address(self.host, self.port)


@dataclass(frozen=True, slots=True)
class NodeRecord:
    """Подписанная адресная запись владельца."""

    node_id: bytes
    identity_public_key: bytes
    addresses: tuple[Address, ...]
    sequence_number: int
    issued_at: int
    expires_at: int
    signature: bytes

    # ------------------------------------------------------------- свойства

    @property
    def record_key(self) -> bytes:
        """Ключ DHT: ``SHA-256("node:" || NodeID)``."""
        return record_key_for_node(self.node_id)

    @property
    def short_id(self) -> str:
        return self.node_id[:6].hex()

    @property
    def ttl_seconds(self) -> int:
        return self.expires_at - self.issued_at

    def is_expired(self, now: float | None = None) -> bool:
        stamp = time.time() if now is None else now
        return self.expires_at <= stamp

    # ----------------------------------------------------------- кодирование

    def signed_payload(self) -> bytes:
        """Канонические байты, по которым вычисляется подпись."""
        return codec.encode_payload(self._unsigned_map())

    def _unsigned_map(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "identity_public_key": self.identity_public_key,
            "addresses": [address.to_cbor() for address in self.addresses],
            "sequence_number": self.sequence_number,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_cbor(self) -> dict[str, Any]:
        payload = self._unsigned_map()
        payload["signature"] = self.signature
        return payload

    def encode(self) -> bytes:
        return codec.encode_payload(self.to_cbor())

    # ------------------------------------------------------------ фабрика

    @classmethod
    def create(
        cls,
        identity: Identity,
        addresses: list[Address] | tuple[Address, ...],
        *,
        sequence_number: int,
        ttl_seconds: int,
        now: float | None = None,
    ) -> NodeRecord:
        """Подписать новую запись собственным долговременным ключом."""
        if not addresses:
            raise BadAddress("at least one address is required")
        if sequence_number < 0:
            raise MalformedRecord("sequence_number must be non-negative")
        if ttl_seconds <= 0:
            raise MalformedRecord("ttl_seconds must be positive")
        stamp = int(time.time() if now is None else now)
        unsigned = cls(
            node_id=identity.node_id,
            identity_public_key=identity.public_key_der,
            addresses=tuple(addresses),
            sequence_number=sequence_number,
            issued_at=stamp,
            expires_at=stamp + ttl_seconds,
            signature=b"",
        )
        signature = identity.sign(unsigned.signed_payload())
        return NodeRecord(
            node_id=unsigned.node_id,
            identity_public_key=unsigned.identity_public_key,
            addresses=unsigned.addresses,
            sequence_number=unsigned.sequence_number,
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
            signature=signature,
        )


def record_key_for_node(node_id: bytes) -> bytes:
    return hashlib.sha256(NODE_KEY_PREFIX + node_id).digest()


def parse_record(obj: Any) -> NodeRecord:
    """Разобрать запись из CBOR-словаря без семантических проверок."""
    if not isinstance(obj, dict):
        raise MalformedRecord("record must be a CBOR map")
    try:
        node_id = obj["node_id"]
        public_key = obj["identity_public_key"]
        raw_addresses = obj["addresses"]
        sequence_number = obj["sequence_number"]
        issued_at = obj["issued_at"]
        expires_at = obj["expires_at"]
        signature = obj["signature"]
    except KeyError as e:
        raise MalformedRecord(f"record misses field {e}") from e
    if not isinstance(node_id, bytes) or not isinstance(public_key, bytes):
        raise MalformedRecord("node_id and identity_public_key must be byte strings")
    if not isinstance(signature, bytes):
        raise MalformedRecord("signature must be a byte string")
    if not isinstance(raw_addresses, list):
        raise MalformedRecord("addresses must be a list")
    for field_name, value in (
        ("sequence_number", sequence_number),
        ("issued_at", issued_at),
        ("expires_at", expires_at),
    ):
        if not isinstance(value, int) or value < 0:
            raise MalformedRecord(f"{field_name} must be a non-negative integer")
    addresses = tuple(Address.from_cbor(item) for item in raw_addresses)
    return NodeRecord(
        node_id=node_id,
        identity_public_key=public_key,
        addresses=addresses,
        sequence_number=sequence_number,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=signature,
    )


def validate_record(
    record: NodeRecord,
    config: NodeConfig,
    *,
    now: float | None = None,
    expected_node_id_bytes: int | None = None,
) -> None:
    """Полная проверка записи перед сохранением или использованием.

    Проверяются: размер, набор адресов, связь ``NodeID`` и ключа, подпись,
    интервал действия. Монотонность ``sequence_number`` проверяет хранилище.
    """
    stamp = time.time() if now is None else now
    expected_bytes = expected_node_id_bytes or config.node_id_bytes

    if len(record.node_id) != expected_bytes:
        raise MalformedRecord(
            f"node_id length {len(record.node_id)} != expected {expected_bytes}"
        )
    if len(record.addresses) == 0:
        raise BadAddress("record must contain at least one address")
    if len(record.addresses) > config.max_addresses:
        raise BadAddress(
            f"record contains {len(record.addresses)} addresses, "
            f"limit is {config.max_addresses}"
        )
    if len(record.signature) != 64:
        raise BadRecordSignature("signature must be 64 bytes")

    encoded_size = len(record.encode())
    if encoded_size > config.max_record_bytes:
        raise RecordTooLarge(
            f"record is {encoded_size} bytes, limit is {config.max_record_bytes}"
        )

    if not verify_node_id(
        record.node_id, record.identity_public_key, len(record.node_id) * 8
    ):
        raise RecordIdentityMismatch("NodeID does not match the record public key")

    key = load_public_key(record.identity_public_key)
    try:
        key.verify(record.signature, record.signed_payload())
    except Exception as e:
        raise BadRecordSignature("record signature is not valid") from e

    if record.expires_at <= record.issued_at:
        raise NotYetValidRecord("expires_at must be greater than issued_at")
    if record.ttl_seconds > config.record_ttl_seconds * 4:
        raise NotYetValidRecord(
            f"record TTL {record.ttl_seconds}s is too large for this network"
        )
    if record.issued_at > stamp + CLOCK_SKEW_SECONDS:
        raise NotYetValidRecord("record is issued in the future")
    if record.expires_at <= stamp:
        raise ExpiredRecord(
            f"record expired at {int(record.expires_at)}, now {int(stamp)}"
        )
