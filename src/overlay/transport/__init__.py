"""Транспортный слой: кадрирование, сериализация payload, TCP-соединения."""

from __future__ import annotations

from .frame import (
    FLAG_ERROR,
    FLAG_FRAGMENT,
    FLAG_RESPONSE,
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
    BadType,
    BadVersion,
    ErrorCode,
    Frame,
    FrameError,
    FrameHeader,
    MsgType,
    PayloadTooLarge,
    ShortHeader,
    short_node_id,
)
from .tcp import Connection, ConnectionHandler, StreamDecoder, connect, serve

__all__ = [
    "FLAG_ERROR",
    "FLAG_FRAGMENT",
    "FLAG_RESPONSE",
    "HEADER_SIZE",
    "MAX_FRAME_PAYLOAD",
    "PROTOCOL_VERSION",
    "BadType",
    "BadVersion",
    "Connection",
    "ConnectionHandler",
    "ErrorCode",
    "Frame",
    "FrameError",
    "FrameHeader",
    "MsgType",
    "PayloadTooLarge",
    "ShortHeader",
    "StreamDecoder",
    "connect",
    "serve",
    "short_node_id",
]
