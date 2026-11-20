"""Сериализация payload: канонический CBOR.

Канонический режим ``cbor2`` сортирует ключи словаря и использует минимальное
представление чисел, поэтому одинаковые логические структуры дают одинаковые
байты. Это свойство необходимо для подписи DHT-записей и канонического
кодирования открытых ключей.
"""

from __future__ import annotations

from typing import Any

import cbor2

from ..errors import ProtocolError


def encode_payload(obj: Any) -> bytes:
    """Сериализовать объект в канонический CBOR."""
    return cbor2.dumps(obj, canonical=True)


def decode_payload(data: bytes) -> Any:
    """Десериализовать CBOR; пустой payload трактуется как пустой словарь."""
    if not data:
        return {}
    try:
        return cbor2.loads(data)
    except Exception as e:  # cbor2 поднимает разные типы, все считаем BAD_PAYLOAD
        raise ProtocolError(f"payload is not valid CBOR: {e}") from e


def decode_mapping(data: bytes) -> dict[str, Any]:
    """Десериализовать payload, который обязан быть словарём."""
    obj = decode_payload(data)
    if not isinstance(obj, dict):
        raise ProtocolError("payload must be a CBOR map")
    return obj
