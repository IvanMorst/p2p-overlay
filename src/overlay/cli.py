from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .config import NodeConfig
from .transport import codec
from .transport.frame import FLAG_RESPONSE, Frame, MsgType
from .transport.tcp import connect, serve


async def _cmd_serve(args: argparse.Namespace) -> None:
    cfg = NodeConfig.load(args.config) if args.config else NodeConfig()

    async def handler(conn) -> None:
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
        await conn._closed.wait()

    server = await serve(cfg.listen_host, cfg.listen_port, handler)
    logging.info("listening on %s:%d", cfg.listen_host, cfg.listen_port)
    async with server:
        await server.serve_forever()


async def _cmd_ping_peer(args: argparse.Namespace) -> None:
    conn = await connect(args.host, args.port)
    try:
        frame = await conn.request(
            MsgType.PING,
            payload=codec.encode_payload({}),
            timeout=args.timeout,
        )
        data = codec.decode_payload(frame.payload)
        print(f"pong type=0x{frame.type:02x} payload={data}")
    finally:
        await conn.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="overlay")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--config", type=Path, default=None)
    p_serve.set_defaults(func=_cmd_serve)

    p_ping = sub.add_parser("ping-peer")
    p_ping.add_argument("--host", required=True)
    p_ping.add_argument("--port", type=int, required=True)
    p_ping.add_argument("--timeout", type=float, default=5.0)
    p_ping.set_defaults(func=_cmd_ping_peer)

    args = parser.parse_args()
    asyncio.run(args.func(args))