import struct

import pytest

from overlay.transport.frame import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
    BadType,
    BadVersion,
    Frame,
    MsgType,
    PayloadTooLarge,
)
from overlay.transport.tcp import StreamDecoder


def _header_bytes(
    *,
    version: int = PROTOCOL_VERSION,
    msg_type: int = int(MsgType.PING),
    flags: int = 0,
    request_id: bytes = b"\x00" * 16,
    payload_length: int = 0,
) -> bytes:
    return struct.pack(">BBH16sI", version, msg_type, flags, request_id, payload_length)


def test_bad_version_rejected() -> None:
    decoder = StreamDecoder()
    with pytest.raises(BadVersion):
        decoder.feed(_header_bytes(version=PROTOCOL_VERSION + 1))


def test_unknown_type_rejected() -> None:
    decoder = StreamDecoder()
    with pytest.raises(BadType):
        decoder.feed(_header_bytes(msg_type=0xEE))


def test_payload_length_rejected_before_allocation() -> None:
    decoder = StreamDecoder()
    raw = _header_bytes(payload_length=MAX_FRAME_PAYLOAD + 1)
    with pytest.raises(PayloadTooLarge):
        decoder.feed(raw)
    assert decoder.buffered == len(raw)


def test_partial_header_does_not_raise() -> None:
    decoder = StreamDecoder()
    assert decoder.feed(b"\x00" * (HEADER_SIZE - 1)) == []


def test_two_frames_in_one_chunk() -> None:
    f1 = Frame(type=MsgType.PING, request_id=Frame.new_request_id(), payload=b"a")
    f2 = Frame(type=MsgType.PING, request_id=Frame.new_request_id(), payload=b"bb")
    decoder = StreamDecoder()
    got = decoder.feed(f1.encode() + f2.encode())
    assert got == [f1, f2]
    assert decoder.buffered == 0