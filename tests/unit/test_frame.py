import struct

import pytest

from overlay.transport.frame import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
    Frame,
    FrameHeader,
    MsgType,
    PayloadTooLarge,
    ShortHeader,
)


def test_header_roundtrip() -> None:
    header = FrameHeader(
        version=PROTOCOL_VERSION,
        type=int(MsgType.PING),
        flags=0,
        request_id=bytes(range(16)),
        payload_length=1234,
    )
    raw = header.pack()
    assert len(raw) == HEADER_SIZE
    restored = FrameHeader.unpack(raw)
    assert restored == header


def test_header_unpack_requires_exact_size() -> None:
    with pytest.raises(ShortHeader):
        FrameHeader.unpack(b"\x00" * (HEADER_SIZE - 1))
    with pytest.raises(ShortHeader):
        FrameHeader.unpack(b"\x00" * (HEADER_SIZE + 1))


def test_header_rejects_wrong_request_id_size() -> None:
    header = FrameHeader(
        version=PROTOCOL_VERSION,
        type=int(MsgType.PING),
        flags=0,
        request_id=b"\x00" * 15,
        payload_length=0,
    )
    with pytest.raises(ValueError):
        header.pack()


def test_header_rejects_payload_too_large_on_pack() -> None:
    header = FrameHeader(
        version=PROTOCOL_VERSION,
        type=int(MsgType.PING),
        flags=0,
        request_id=b"\x00" * 16,
        payload_length=MAX_FRAME_PAYLOAD + 1,
    )
    with pytest.raises(PayloadTooLarge):
        header.pack()


def test_payload_length_is_big_endian_uint32() -> None:
    request_id = bytes(range(16))
    header = FrameHeader(
        version=PROTOCOL_VERSION,
        type=int(MsgType.PING),
        flags=0,
        request_id=request_id,
        payload_length=0x01020304,
    )
    raw = header.pack()
    length_bytes = raw[20:24]
    assert length_bytes == b"\x01\x02\x03\x04"
    assert struct.unpack(">I", length_bytes)[0] == 0x01020304


def test_frame_encode_concatenates_header_and_payload() -> None:
    payload = b"hello"
    frame = Frame(
        type=MsgType.PING,
        request_id=b"\x01" * 16,
        payload=payload,
    )
    raw = frame.encode()
    assert raw[:HEADER_SIZE] == frame.header.pack()
    assert raw[HEADER_SIZE:] == payload


def test_frame_new_request_id_is_unique_and_16_bytes() -> None:
    a = Frame.new_request_id()
    b = Frame.new_request_id()
    assert len(a) == 16
    assert len(b) == 16
    assert a != b