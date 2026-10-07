from __future__ import annotations

import enum
import struct
import uuid
from dataclasses import dataclass

PROTOCOL_VERSION = 1
HEADER_SIZE = 24
MAX_FRAME_PAYLOAD = 65_536

_HEADER = struct.Struct(">BBH16sI")


class MsgType(enum.IntEnum):
    PING = 0x01
    PONG = 0x02
    FIND_NODE_REQUEST = 0x10
    FIND_NODE_RESPONSE = 0x11
    STORE_REQUEST = 0x20
    STORE_RESPONSE = 0x21
    FIND_VALUE_REQUEST = 0x30
    FIND_VALUE_RESPONSE = 0x31
    TUNNEL_BUILD = 0x40
    TUNNEL_BUILD_OK = 0x41
    TUNNEL_BUILD_FAIL = 0x42
    TUNNEL_DATA = 0x43
    TUNNEL_ACK = 0x44
    TUNNEL_CLOSE = 0x45
    APP_MESSAGE = 0x50
    APP_ACK = 0x51
    ERROR = 0x7F


class ErrorCode(enum.IntEnum):
    BAD_VERSION = 0x01
    BAD_TYPE = 0x02
    PAYLOAD_TOO_LARGE = 0x03
    BAD_PAYLOAD = 0x04
    UNEXPECTED_REQUEST_ID = 0x05
    TIMEOUT = 0x06
    INTERNAL = 0x07


FLAG_RESPONSE = 0x0001
FLAG_ERROR = 0x0002
FLAG_FRAGMENT = 0x0004
KNOWN_FLAGS = FLAG_RESPONSE | FLAG_ERROR | FLAG_FRAGMENT


class FrameError(Exception):
    """Базовая ошибка кадрирования."""


class BadVersion(FrameError):
    pass


class BadType(FrameError):
    pass


class PayloadTooLarge(FrameError):
    pass


class ShortHeader(FrameError):
    pass


@dataclass(slots=True)
class FrameHeader:
    version: int
    type: int
    flags: int
    request_id: bytes
    payload_length: int

    def pack(self) -> bytes:
        if len(self.request_id) != 16:
            raise ValueError("request_id must be 16 bytes")
        if self.payload_length < 0 or self.payload_length > MAX_FRAME_PAYLOAD:
            raise PayloadTooLarge(self.payload_length)
        return _HEADER.pack(
            self.version,
            self.type,
            self.flags,
            self.request_id,
            self.payload_length,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "FrameHeader":
        if len(raw) != HEADER_SIZE:
            raise ShortHeader(f"expected {HEADER_SIZE}, got {len(raw)}")
        version, mtype, flags, request_id, payload_length = _HEADER.unpack(raw)
        return cls(version, mtype, flags, request_id, payload_length)


@dataclass(slots=True)
class Frame:
    type: int
    request_id: bytes
    payload: bytes = b""
    flags: int = 0
    version: int = PROTOCOL_VERSION

    @property
    def header(self) -> FrameHeader:
        return FrameHeader(
            version=self.version,
            type=self.type,
            flags=self.flags,
            request_id=self.request_id,
            payload_length=len(self.payload),
        )

    def encode(self) -> bytes:
        return self.header.pack() + self.payload

    @staticmethod
    def new_request_id() -> bytes:
        return uuid.uuid4().bytes