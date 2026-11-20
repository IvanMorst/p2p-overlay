"""Тест-векторы XOR-метрики и разбиения на bucket."""

from __future__ import annotations

import pytest

from overlay.dht.xor import bucket_index, distance_key, leading_zero_bits, xor_bytes, xor_distance


def test_xor_distance_basic_vectors() -> None:
    a = bytes([0b1010])
    b = bytes([0b0110])
    assert xor_distance(a, b) == 0b1100
    assert xor_distance(a, a) == 0
    assert xor_distance(a, b) == xor_distance(b, a)


def test_xor_distance_full_width() -> None:
    one = (1).to_bytes(32, "big")
    two = (2).to_bytes(32, "big")
    assert xor_distance(one, two) == 3
    zero = bytes(32)
    assert xor_distance(one, zero) == 1


def test_xor_distance_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError):
        xor_distance(b"\x00", b"\x00\x00")


def test_xor_bytes_and_symmetry() -> None:
    a = bytes(range(8))
    b = bytes(range(8, 16))
    assert xor_bytes(a, b) == xor_bytes(b, a)
    assert int.from_bytes(xor_bytes(a, b), "big") == xor_distance(a, b)


def test_leading_zero_bits() -> None:
    a = bytes([0b1000_0000])
    b = bytes([0b1100_0000])
    assert leading_zero_bits(a, b) == 1
    assert leading_zero_bits(a, a) == 8


def test_bucket_index_matches_distance() -> None:
    local = bytes(32)
    assert bucket_index(local, local) is None
    one = (1).to_bytes(32, "big")
    assert bucket_index(local, one) == 0
    two = (2).to_bytes(32, "big")
    assert bucket_index(local, two) == 1
    top = (1 << 255).to_bytes(32, "big")
    assert bucket_index(local, top) == 255


def test_distance_key_sorting() -> None:
    local = b"\x00" * 4
    targets = [b"\x00\x00\x00\x03", b"\x00\x00\x00\x01", b"\x00\x00\x01\x00"]
    ordered = sorted(targets, key=lambda t: distance_key(local, t))
    assert ordered == [b"\x00\x00\x00\x01", b"\x00\x00\x00\x03", b"\x00\x00\x01\x00"]
