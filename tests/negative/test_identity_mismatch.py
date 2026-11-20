"""Негативные тесты идентичности: подмена ключа, NodeID и роли сервера."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from overlay.config import NodeConfig
from overlay.dht.contact import Contact
from overlay.errors import HandshakeError, RemoteError
from overlay.identity import Identity
from overlay.node import Node
from overlay.transport import codec
from overlay.transport.frame import MsgType
from overlay.transport.tcp import connect


def _config(tmp_path: Path, port: int = 0) -> NodeConfig:
    config = NodeConfig(
        node_id_bits=256,
        state_dir=tmp_path,
        listen_host="127.0.0.1",
        listen_port=port,
        security_mode="plain",
        request_timeout_seconds=2.0,
        connect_timeout_seconds=2.0,
        metrics_enabled=False,
    )
    config.validate()
    return config


async def test_hello_with_foreign_node_id_is_rejected(tmp_path: Path) -> None:
    server_node = Node(_config(tmp_path / "server"))
    await server_node.start()
    try:
        attacker = Identity.generate()
        other = Identity.generate()
        conn = await connect("127.0.0.1", server_node.bound_port)
        try:
            # Заявлен NodeID одного узла, а предъявлен ключ другого.
            payload = codec.encode_payload(
                {
                    "version": 1,
                    "node_id": attacker.node_id,
                    "key": other.public_key_der,
                    "host": "127.0.0.1",
                    "port": 1234,
                }
            )
            with pytest.raises((RemoteError, HandshakeError, ConnectionError)):
                await conn.request(
                    MsgType.HELLO,
                    payload=payload,
                    timeout=2.0,
                    expected_type=MsgType.HELLO_OK,
                )
        finally:
            await conn.close()
        # Узел продолжает обслуживать корректные соединения.
        good = await connect("127.0.0.1", server_node.bound_port)
        try:
            reply = await good.request(
                MsgType.HELLO,
                payload=codec.encode_payload(
                    {
                        "version": 1,
                        "node_id": attacker.node_id,
                        "key": attacker.public_key_der,
                        "host": "127.0.0.1",
                        "port": 1234,
                    }
                ),
                timeout=2.0,
                expected_type=MsgType.HELLO_OK,
            )
            assert reply.type == MsgType.HELLO_OK
        finally:
            await good.close()
    finally:
        await server_node.stop()


async def test_dial_with_wrong_expected_node_id_fails(lab) -> None:
    """Запись с чужим NodeID, указывающая на адрес жертвы, не принимается."""
    node = lab.node(1)
    victim = lab.node(0)
    forged_key = Identity.generate()
    forged = Contact(
        node_id=forged_key.node_id,
        public_key_der=forged_key.public_key_der,
        host="127.0.0.1",
        port=victim.bound_port,
    )
    with pytest.raises(HandshakeError):
        await node.peers.dial(forged, expected_node_id=forged_key.node_id)

    # Кэш не обходится: несовпадение ожидаемого идентификатора с контактом
    # отклоняется ещё до установления соединения.
    real_contact = victim.peers.local_contact
    with pytest.raises(HandshakeError):
        await node.peers.dial(real_contact, expected_node_id=forged_key.node_id)


async def test_node_rejects_self_connection(lab) -> None:
    node = lab.node(0)
    with pytest.raises(HandshakeError):
        await node.peers.dial_address("127.0.0.1", node.bound_port)


async def test_garbage_frame_does_not_kill_node(tmp_path: Path) -> None:
    """Нарушение кадрирования закрывает соединение, но узел продолжает работу."""
    server_node = Node(_config(tmp_path / "server"))
    await server_node.start()
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", server_node.bound_port)
        writer.write(b"\x09" * 5)  # неверная версия в заголовке
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()
        await writer.wait_closed()
        # Узел жив: принимает корректное соединение и отвечает на HELLO.
        peer = Identity.generate()
        conn = await connect("127.0.0.1", server_node.bound_port)
        try:
            reply = await conn.request(
                MsgType.HELLO,
                payload=codec.encode_payload(
                    {
                        "version": 1,
                        "node_id": peer.node_id,
                        "key": peer.public_key_der,
                        "host": "127.0.0.1",
                        "port": 1234,
                    }
                ),
                timeout=2.0,
                expected_type=MsgType.HELLO_OK,
            )
            assert reply.type == MsgType.HELLO_OK
        finally:
            await conn.close()
    finally:
        await server_node.stop()
