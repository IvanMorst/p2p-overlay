"""Интеграционные тесты защищённого канала (TLS 1.3, mTLS)."""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path
from typing import Any

import pytest

from overlay.dht.contact import Contact
from overlay.dht.record import record_key_for_node
from overlay.errors import HandshakeError
from overlay.security.base import SecurityError
from overlay.transport import codec, connect
from overlay.transport.frame import Frame, MsgType
from overlay.transport.tcp import Connection
from tests.lab import Lab, LabParams, make_lab
from tests.proxy import RecordingProxy, application_records

MARKER = "SECRET-APP-PAYLOAD-9f3c2b"


@pytest.fixture
async def tls_lab(tmp_path: Path) -> Lab:
    stand = make_lab(tmp_path, LabParams(n=5, security_mode="tls13"))
    await stand.start()
    try:
        yield stand
    finally:
        await stand.stop()


def _via_proxy(node: Any, port: int) -> Contact:
    return Contact(
        node_id=node.node_id,
        public_key_der=node.identity.public_key_der,
        host="127.0.0.1",
        port=port,
    )


async def _capture_session(
    client: Any, server: Any
) -> tuple[RecordingProxy, bytes]:
    """Открыть сессию клиент-сервер через прокси и вернуть записанный трафик."""
    # Кэш соединений нужно сбросить, иначе клиент пойдёт напрямую.
    client.peers.forget(server.node_id)
    await asyncio.sleep(0)
    proxy = RecordingProxy(target_host="127.0.0.1", target_port=server.bound_port)
    await proxy.start()
    try:
        conn = await client.peers.dial(_via_proxy(server, proxy.port))
        await conn.request(
            MsgType.PING,
            payload=codec.encode_payload({"marker": MARKER}),
            timeout=3.0,
            expected_type=MsgType.PONG,
        )
        await conn.close()
    finally:
        await proxy.stop()
    return proxy, bytes(proxy.client_to_server)


async def _send_raw(port: int, data: bytes) -> bytes:
    """Отправить байты в открытый TCP-порт и вернуть ответ (может быть пустым)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(data)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except (TimeoutError, asyncio.IncompleteReadError):
            return b""
    finally:
        writer.close()
        with __import__("contextlib").suppress(Exception):
            await writer.wait_closed()


async def test_all_connections_use_tls13(tls_lab: Lab) -> None:
    node = tls_lab.node(2)
    contact = tls_lab.node(0).peers.local_contact
    conn = await node.peers.dial(contact)
    assert conn.tls_version == "TLSv1.3"
    assert conn.tls_cipher.startswith("TLS_")
    assert conn.peer_certificate_der is not None


async def test_peer_certificate_binds_identity(tls_lab: Lab) -> None:
    """Ключ сертификата совпадает с ключом из HELLO и с NodeID."""
    node = tls_lab.node(1)
    target = tls_lab.node(3)
    conn = await node.peers.dial(target.peers.local_contact)
    peer = node.security.peer_identity(conn)  # type: ignore[attr-defined]
    assert peer is not None
    assert peer.node_id == target.node_id
    assert peer.public_key_der == target.identity.public_key_der


async def test_dht_works_over_secure_channel(tls_lab: Lab) -> None:
    """E4-6: PING, FIND_NODE, STORE и FIND_VALUE через TLS без открытого режима."""
    initiator = tls_lab.node(4)
    target = tls_lab.node(2)
    tls_lab.hide_contact(4, 2)
    assert initiator.table.get(target.node_id) is None

    lookup = await initiator.lookup_node(target.node_id)
    assert target.node_id in lookup.contact_ids

    contact = await initiator.resolve_contact(target.node_id)
    assert contact.node_id == target.node_id
    assert await initiator.rpc.ping(contact) is True

    key = record_key_for_node(target.node_id)
    initiator.storage.delete(key)
    found = await initiator.get_record(key)
    assert found is not None and found.node_id == target.node_id


async def test_tls12_client_is_rejected(tls_lab: Lab) -> None:
    address = tls_lab.node(0).peers.local_contact
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises((ssl.SSLError, OSError, ConnectionError)):
        await connect(address.host, address.port, ssl_context=context, timeout=3.0)


async def test_client_without_certificate_is_rejected(tls_lab: Lab) -> None:
    """Взаимная аутентификация: клиент без сертификата не проходит проверку.

    TLS 1.3 завершает рукопожатие на стороне клиента до того, как сервер
    проверит отсутствие клиентского сертификата, поэтому отказ проявляется на
    первом прикладном обмене: ``certificate required`` и разрыв соединения.
    """
    address = tls_lab.node(0).peers.local_contact
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    conn = await connect(address.host, address.port, ssl_context=context, timeout=3.0)
    try:
        with pytest.raises((ssl.SSLError, OSError, ConnectionError)):
            await conn.request(MsgType.PING, timeout=3.0, expected_type=MsgType.PONG)
    finally:
        await conn.close()


async def test_wrong_expected_node_id_is_rejected(tls_lab: Lab) -> None:
    node = tls_lab.node(1)
    contact = tls_lab.node(0).peers.local_contact
    with pytest.raises((HandshakeError, SecurityError)):
        await node.peers.dial(contact, expected_node_id=b"\x01" * 32)


async def test_application_payload_is_not_visible_on_wire(tls_lab: Lab) -> None:
    """Контрольный pcap-тест: в перехваченном потоке нет открытого текста."""
    server = tls_lab.node(0)
    client = tls_lab.node(1)

    proxy, client_stream = await _capture_session(client, server)
    captured = bytes(proxy.client_to_server) + bytes(proxy.server_to_client)

    assert captured, "прокси не записал ни одного байта"
    assert MARKER.encode() not in captured
    for field in (b"FIND_NODE", b"APP_MESSAGE", b"marker", b"node_id"):
        assert field not in captured
    assert application_records(client_stream), "должны присутствовать записи application_data"
    assert client_stream[0] == 0x16, "первая запись должна быть TLS handshake"


async def test_tampered_ciphertext_is_rejected(tls_lab: Lab) -> None:
    """Изменение ciphertext не приводит к прикладному действию."""
    server = tls_lab.node(0)
    client = tls_lab.node(1)
    _proxy, client_stream = await _capture_session(client, server)

    records = application_records(client_stream)
    assert records
    tampered = bytearray(records[0])
    tampered[-1] ^= 0xFF

    response = await _send_raw(server.bound_port, bytes(tampered))
    assert response == b""
    # Узел продолжает обслуживать корректные соединения.
    assert await client.rpc.ping(server.peers.local_contact) is True


async def test_cross_session_replay_is_rejected(tls_lab: Lab) -> None:
    """Повтор записанного кадра из завершённой сессии не выполняется."""
    server = tls_lab.node(0)
    client = tls_lab.node(1)
    _proxy, client_stream = await _capture_session(client, server)

    records = application_records(client_stream)
    assert records

    response = await _send_raw(server.bound_port, records[0])
    assert response == b""
    assert await client.rpc.ping(server.peers.local_contact) is True


async def test_replayed_frame_in_session_does_not_repeat_action(tls_lab: Lab) -> None:
    """Повтор кадра внутри защищённой сессии: ERROR 0x0A и отказ от обработки."""
    server = tls_lab.node(0)
    client = tls_lab.node(1)
    context = client.security.client_context()  # type: ignore[attr-defined]
    conn: Connection = await connect(
        "127.0.0.1", server.bound_port, ssl_context=context, timeout=3.0
    )
    incoming: asyncio.Queue[Frame] = asyncio.Queue()

    async def collect(frame: Frame) -> None:
        incoming.put_nowait(frame)

    conn.set_handler(collect)
    try:
        client.security.verify_peer(conn, server.node_id)  # type: ignore[attr-defined]
        assert conn.tls_version == "TLSv1.3"
        await conn.request(
            MsgType.HELLO,
            payload=codec.encode_payload(client.peers.hello_payload()),
            timeout=3.0,
            expected_type=MsgType.HELLO_OK,
        )

        frame = Frame(
            type=MsgType.PING, request_id=b"\xAB" * 16, payload=codec.encode_payload({})
        )
        before = server.service.requests_in
        await conn.send(frame)
        await _wait_for_condition(lambda: server.service.requests_in == before + 1)
        assert server.service.requests_in == before + 1

        await conn.send(frame)  # тот же request_id повторно
        error = await asyncio.wait_for(incoming.get(), timeout=3.0)
        assert error.type == MsgType.ERROR
        assert codec.decode_payload(error.payload)["code"] == 0x0A
        # Повторной обработки не произошло.
        assert server.service.requests_in == before + 1
    finally:
        await conn.close()


async def _wait_for_condition(predicate: Any, *, timeout: float = 3.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not met in time")
