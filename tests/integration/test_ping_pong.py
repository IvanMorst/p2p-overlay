import asyncio

import pytest

from overlay.transport import codec
from overlay.transport.frame import FLAG_RESPONSE, Frame, MsgType
from overlay.transport.tcp import Connection, connect, serve


@pytest.mark.asyncio
async def test_ping_pong_between_two_nodes() -> None:
    async def handler(conn: Connection) -> None:
        async def on_frame(frame: Frame) -> None:
            if frame.type == MsgType.PING:
                reply = Frame(
                    type=MsgType.PONG,
                    request_id=frame.request_id,
                    payload=codec.encode_payload({"ok": True}),
                    flags=FLAG_RESPONSE,
                )
                await conn.send(reply)

        conn.set_handler(on_frame)
        await conn.wait_closed()

    server = await serve("127.0.0.1", 0, handler)
    port = server.sockets[0].getsockname()[1]
    try:
        conn = await connect("127.0.0.1", port)
        try:
            frame = await conn.request(
                MsgType.PING,
                payload=codec.encode_payload({}),
                timeout=2.0,
                expected_type=MsgType.PONG,
            )
            assert frame.type == MsgType.PONG
            assert codec.decode_payload(frame.payload) == {"ok": True}
        finally:
            await conn.close()
    finally:
        server.close()
        await server.wait_closed()