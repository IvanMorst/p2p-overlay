"""Интеграционные тесты туннеля и прикладных сообщений (этап 5)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from overlay.errors import TunnelError
from overlay.tunnel.manager import TunnelState
from tests.lab import Lab, LabParams, make_lab


@pytest.fixture
async def tunnel_lab(tmp_path: Path) -> Lab:
    stand = make_lab(
        tmp_path,
        LabParams(
            n=5,
            security_mode="tls13",
            tunnel_build_timeout=5.0,
            tunnel_data_timeout=2.0,
            tunnel_health_interval=0.5,
        ),
    )
    await stand.start()
    try:
        yield stand
    finally:
        await stand.stop()


async def test_tunnel_has_required_relays_and_states(tunnel_lab: Lab) -> None:
    """Контрольный результат этапа 5: туннель через два ретранслятора."""
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)

    tunnel = await source.build_tunnel(target.node_id)

    assert tunnel.state is TunnelState.ACTIVE
    assert len(tunnel.relays) == source.config.tunnel_min_relays
    assert len(tunnel.relays) >= 2
    hops = tunnel.hops(source.node_id)
    assert hops[0] == source.node_id[:6].hex()
    assert hops[-1] == target.node_id[:6].hex()
    assert len(hops) == len(tunnel.relays) + 2
    assert len(set(tunnel.relays)) == len(tunnel.relays)  # без петель и дублей
    states = [event.state for event in tunnel.events]
    assert states[0] == "BUILDING"
    assert states[-1] == "ACTIVE"


async def test_tunnel_e2e_session_is_tls13(tunnel_lab: Lab) -> None:
    source = tunnel_lab.node(1)
    target = tunnel_lab.node(3)
    tunnel = await source.build_tunnel(target.node_id)
    assert tunnel.e2e is not None
    assert tunnel.e2e.ready
    assert tunnel.e2e.tls_version == "TLSv1.3"
    assert tunnel.e2e.peer is not None
    assert tunnel.e2e.peer.node_id == target.node_id


async def test_message_delivered_through_tunnel(tunnel_lab: Lab) -> None:
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)
    text = "сообщение через туннель"

    record = await source.send_message(target.node_id, text)

    assert record.status == "delivered"
    assert record.direction == "out"
    assert len(record.hops) == source.config.tunnel_min_relays + 2
    assert record.latency_s is not None and record.latency_s > 0
    received = target.messages.history()
    assert len(received) == 1
    assert received[0]["text"] == text
    assert received[0]["direction"] == "in"
    assert received[0]["peer"] == source.node_id[:6].hex()


async def test_relay_sees_only_ciphertext(tunnel_lab: Lab) -> None:
    """Промежуточный ретранслятор не видит открытый прикладной текст."""
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)
    marker = "SECRET-TUNNEL-TEXT-4f21"
    tunnel = await source.build_tunnel(target.node_id)

    captured: list[bytes] = []
    original = tunnel.entry_conn.send

    async def spy(frame):  # type: ignore[no-untyped-def]
        captured.append(bytes(frame.payload))
        await original(frame)

    tunnel.entry_conn.send = spy  # type: ignore[method-assign]
    try:
        await source.send_message(target.node_id, marker)
    finally:
        tunnel.entry_conn.send = original  # type: ignore[method-assign]

    assert captured
    plaintext = marker.encode()
    for payload in captured:
        assert plaintext not in payload
        assert b"app_message" not in payload
    # Полезная нагрузка туннеля начинается с TLS-записи application_data.
    tls_records = [p for p in captured if b"\x17\x03\x03" in p]
    assert tls_records, "в кадрах туннеля должны быть записи application_data"


async def test_tunnel_recovers_after_relay_failure(tunnel_lab: Lab) -> None:
    """Остановка ретранслятора приводит к автоматическому построению маршрута."""
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)
    tunnel = await source.build_tunnel(target.node_id)
    failed_relay = tunnel.relays[1]
    index = next(
        i for i in tunnel_lab.active if tunnel_lab.node(i).node_id == failed_relay.node_id
    )

    await tunnel_lab.stop_node(index)

    record = await source.send_message(target.node_id, "после отказа ретранслятора")

    assert record.status == "delivered"
    assert source.tunnels.rebuilds >= 1
    assert failed_relay.node_id not in [
        tunnel_lab.node(i).node_id
        for i in tunnel_lab.active
        if tunnel_lab.node(i).node_id == failed_relay.node_id
    ]
    new_hops = record.hops
    assert failed_relay.short_id not in new_hops
    assert target.node_id[:6].hex() in new_hops
    assert len(new_hops) == source.config.tunnel_min_relays + 2


async def test_repeated_message_is_not_processed_twice(tunnel_lab: Lab) -> None:
    """Повтор с тем же message_id не создаёт второго прикладного действия."""
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)
    tunnel = await source.build_tunnel(target.node_id)
    message_id = b"\x42" * 16
    payload = {
        "kind": "app_message",
        "message_id": message_id,
        "from": source.node_id,
        "text": "повтор",
        "sent_at": 1.0,
    }

    first = await source.tunnels.request(tunnel, payload)
    second = await source.tunnels.request(tunnel, payload)

    assert first["status"] == "delivered"
    assert second["status"] == "duplicate"
    assert target.messages.duplicates == 1
    assert len(target.messages.history()) == 1


async def test_insufficient_relays_fails_without_direct_fallback(tmp_path: Path) -> None:
    """При нехватке ретрансляторов туннель не строится и прямая доставка не используется."""
    stand = make_lab(
        tmp_path,
        LabParams(n=3, security_mode="tls13", tunnel_build_timeout=2.0),
    )
    await stand.start()
    try:
        with pytest.raises(TunnelError):
            await stand.node(0).build_tunnel(stand.node(2).node_id)
        with pytest.raises(TunnelError):
            await stand.node(0).send_message(stand.node(2).node_id, "нет маршрута")
        assert stand.node(2).messages.history() == []
    finally:
        await stand.stop()


async def test_tunnel_close_releases_relays(tunnel_lab: Lab) -> None:
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)
    tunnel = await source.build_tunnel(target.node_id)
    relay_index = next(
        i
        for i in tunnel_lab.active
        if tunnel_lab.node(i).node_id == tunnel.relays[0].node_id
    )
    relay = tunnel_lab.node(relay_index)
    assert tunnel.tunnel_id in relay.tunnels._relays

    await source.close_tunnel(tunnel.tunnel_id)
    await asyncio.sleep(0.1)

    assert source.tunnels.get(tunnel.tunnel_id) is None
    assert tunnel.tunnel_id not in relay.tunnels._relays


async def test_send_via_tunnel_raw_payload(tunnel_lab: Lab) -> None:
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(3)
    tunnel = await source.build_tunnel(target.node_id)

    seq = await source.send_via_tunnel(tunnel.tunnel_id, b"\x01\x02\x03")

    assert seq >= 1
    with pytest.raises(TunnelError):
        await source.send_via_tunnel(b"\x00" * 16, b"x")


async def test_health_probe_keeps_tunnel_active(tunnel_lab: Lab) -> None:
    source = tunnel_lab.node(0)
    target = tunnel_lab.node(4)
    tunnel = await source.build_tunnel(target.node_id)
    await asyncio.sleep(1.2)  # больше двух интервалов health
    assert tunnel.last_ack_at > 0
    assert tunnel.state in {TunnelState.ACTIVE, TunnelState.DEGRADED}
    record = await source.send_message(target.node_id, "после health")
    assert record.status == "delivered"
