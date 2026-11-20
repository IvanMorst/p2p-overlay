"""XOR-метрика Kademlia.

Расстояние между идентификаторами — побитовое исключающее ИЛИ, интерпретируемое
как беззнаковое целое. Метрика удовлетворяет аксиомам: d(a,a)=0, симметрия,
неравенство треугольника.
"""

from __future__ import annotations


def xor_distance(a: bytes, b: bytes) -> int:
    """Расстояние XOR между двумя идентификаторами равной длины."""
    if len(a) != len(b):
        raise ValueError(f"identifier length mismatch: {len(a)} != {len(b)}")
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"identifier length mismatch: {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def leading_zero_bits(a: bytes, b: bytes) -> int:
    """Длина общего префикса в битах."""
    distance = xor_distance(a, b)
    if distance == 0:
        return len(a) * 8
    return len(a) * 8 - distance.bit_length()


def bucket_index(local_id: bytes, other_id: bytes) -> int | None:
    """Индекс k-bucket для контакта.

    Bucket ``i`` хранит контакты с расстоянием в диапазоне
    ``[2**i, 2**(i+1))``. Для собственного идентификатора возвращается ``None``.
    """
    if local_id == other_id:
        return None
    if len(local_id) != len(other_id):
        raise ValueError("identifier length mismatch")
    return xor_distance(local_id, other_id).bit_length() - 1


def distance_key(local_id: bytes, other_id: bytes) -> int:
    """Ключ сортировки по возрастанию XOR-близости."""
    return xor_distance(local_id, other_id)
