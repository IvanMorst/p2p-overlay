"""Интеграционные тесты транспортного уровня (этап 1: TCP и кадрирование)."""

from __future__ import annotations

import asyncio

import pytest

from overlay.errors import ProtocolError, TimeoutExpired
from overlay.transport import codec
from overlay.transport.frame import FLAG_ERROR, FLAG_RESPONSE, Frame, MsgType
from overlay.transport.tcp import Connection, connect, serve


async def _echo_server() -> tuple[asyncio.Server, int]:
    async def handler(conn: Connection) -> None:
        async def on_frame(frame: Frame) -> None:
            if frame.type == MsgType.PING:
                await conn.send(
                    Frame(
                        type=MsgType.PONG,
                        request_id=frame.request_id,
                        payload=codec.encode_payload({"ok": True, "echo": frame.payload}),
                        flags=FLAG_RESPONSE,
                    )
                )

        conn.set_handler(on_frame)
        await conn.wait_closed()

    server = await serve("127.0.0.1", 0, handler)
    port = server.sockets[0].getsockname()[1]
    return server, int(port)


async def test_ping_pong_between_two_nodes() -> None:
    server, port = await _echo_server()
    try:
        conn = await connect("127.0.0.1", port)
        try:
            frame = await conn.request(
                MsgType.PING,
                payload=codec.encode_payload({"hello": "world"}),
                timeout=2.0,
                expected_type=MsgType.PONG,
            )
            assert frame.type == MsgType.PONG
            data = codec.decode_payload(frame.payload)
            assert data["ok"] is True
            assert codec.decode_payload(data["echo"]) == {"hello": "world"}
        finally:
            await conn.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_response_with_foreign_request_id_is_not_accepted() -> None:
    """Ответ с чужим request_id не закрывает ожидание (E1-6)."""

    async def handler(conn: Connection) -> None:
        async def on_frame(frame: Frame) -> None:
            await conn.send(
                Frame(
                    type=MsgType.PONG,
                    request_id=b"\x11" * 16,
                    payload=codec.encode_payload({"ok": True}),
                    flags=FLAG_RESPONSE,
                )
            )

        conn.set_handler(on_frame)
        await conn.wait_closed()

    server = await serve("127.0.0.1", 0, handler)
    port = int(server.sockets[0].getsockname()[1])
    try:
        conn = await connect("127.0.0.1", port)
        try:
            with pytest.raises(TimeoutExpired):
                await conn.request(MsgType.PING, timeout=0.4, expected_type=MsgType.PONG)
        finally:
            await conn.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_unexpected_response_type_is_rejected() -> None:
    async def handler(conn: Connection) -> None:
        async def on_frame(frame: Frame) -> None:
            await conn.send(
                Frame(
                    type=MsgType.FIND_NODE_RESPONSE,
                    request_id=frame.request_id,
                    payload=codec.encode_payload({"contacts": []}),
                    flags=FLAG_RESPONSE,
                )
            )

        conn.set_handler(on_frame)
        await conn.wait_closed()

    server = await serve("127.0.0.1", 0, handler)
    port = int(server.sockets[0].getsockname()[1])
    try:
        conn = await connect("127.0.0.1", port)
        try:
            with pytest.raises(ProtocolError):
                await conn.request(MsgType.PING, timeout=2.0, expected_type=MsgType.PONG)
        finally:
            await conn.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_error_frame_becomes_remote_error() -> None:
    async def handler(conn: Connection) -> None:
        async def on_frame(frame: Frame) -> None:
            await conn.send(
                Frame(
                    type=MsgType.ERROR,
                    request_id=frame.request_id,
                    payload=codec.encode_payload({"code": 0x02, "detail": "unsupported"}),
                    flags=FLAG_ERROR,
                )
            )

        conn.set_handler(on_frame)
        await conn.wait_closed()

    server = await serve("127.0.0.1", 0, handler)
    port = int(server.sockets[0].getsockname()[1])
    try:
        conn = await connect("127.0.0.1", port)
        try:
            with pytest.raises(Exception) as excinfo:
                await conn.request(MsgType.PING, timeout=2.0, expected_type=MsgType.PONG)
            assert "unsupported" in str(excinfo.value)
        finally:
            await conn.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_many_variable_frames_over_tcp() -> None:
    """100 кадров переменной длины принимаются без нарушения границ."""
    received: list[Frame] = []

    async def handler(conn: Connection) -> None:
        async def on_frame(frame: Frame) -> None:
            received.append(frame)
            await conn.send(
                Frame(
                    type=MsgType.PONG,
                    request_id=frame.request_id,
                    payload=frame.payload,
                    flags=FLAG_RESPONSE,
                )
            )

        conn.set_handler(on_frame)
        await conn.wait_closed()

    server = await serve("127.0.0.1", 0, handler)
    port = int(server.sockets[0].getsockname()[1])
    try:
        conn = await connect("127.0.0.1", port)
        try:
            expected = []
            for index in range(100):
                payload = bytes([index]) * (index % 97)
                expected.append(payload)
                frame = await conn.request(
                    MsgType.PING, payload=payload, timeout=3.0, expected_type=MsgType.PONG
                )
                assert frame.payload == payload
            assert [frame.payload for frame in received] == expected
        finally:
            await conn.close()
    finally:
        server.close()
        await server.wait_closed()
