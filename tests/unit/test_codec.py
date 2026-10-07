from overlay.transport import codec


def test_codec_roundtrip_dict() -> None:
    obj = {"ok": True, "n": 42, "name": "node"}
    data = codec.encode_payload(obj)
    assert codec.decode_payload(data) == obj


def test_codec_roundtrip_bytes() -> None:
    obj = {"blob": b"\x00\x01\x02\xff"}
    data = codec.encode_payload(obj)
    restored = codec.decode_payload(data)
    assert restored == obj
    assert isinstance(restored["blob"], bytes)


def test_codec_canonical_is_deterministic() -> None:
    obj1 = {"b": 2, "a": 1}
    obj2 = {"a": 1, "b": 2}
    assert codec.encode_payload(obj1) == codec.encode_payload(obj2)