"""Интеграционные тесты DHT: bootstrap, итеративный поиск, PING-FIND_NODE."""

from __future__ import annotations

from tests.lab import Lab, LabParams, make_lab


async def test_lookup_finds_target_absent_from_initiator_table(lab: Lab) -> None:
    """Контрольный результат этапа 2: цель отсутствует в таблице инициатора."""
    initiator = lab.node(3)
    target = lab.node(4)
    assert lab.hide_contact(3, 4) or target.node_id not in initiator.table
    assert initiator.table.get(target.node_id) is None

    result = await initiator.lookup_node(target.node_id)

    assert target.node_id in result.contact_ids
    assert result.iterations >= 1
    assert result.rpc_count >= 1
    assert result.timeouts == 0
    assert result.duration_s >= 0.0
    # Поиск шёл через промежуточный узел: в первой итерации опрошен не только
    # сам целевой узел (он и не мог быть опрошен первым, так как неизвестен).
    first_step = result.steps[0]
    assert first_step.queried


async def test_lookup_trace_contains_required_fields(lab: Lab) -> None:
    initiator = lab.node(2)
    target = lab.node(3)
    lab.hide_contact(2, 3)
    result = await initiator.lookup_node(target.node_id)
    payload = result.to_dict()
    for field in (
        "lookup_id",
        "initiator",
        "target",
        "iterations",
        "rpc_count",
        "timeouts",
        "errors",
        "duration_s",
        "steps",
        "result_contacts",
    ):
        assert field in payload
    assert payload["initiator"] == initiator.node_id.hex()
    assert payload["target"] == target.node_id.hex()


async def test_lookup_uses_at_most_alpha_parallel_requests(lab: Lab) -> None:
    initiator = lab.node(1)
    result = await initiator.lookup_node(lab.node(2).node_id)
    for step in result.steps:
        assert len(step.queried) <= lab.params.alpha


async def test_find_node_returns_contacts_in_xor_order(lab: Lab) -> None:
    initiator = lab.node(1)
    peer = lab.node(0)
    contacts = await initiator.rpc.find_node(peer.peers.local_contact, initiator.node_id)
    assert len(contacts) <= lab.params.k
    distances = [
        int.from_bytes(initiator.node_id, "big") ^ int.from_bytes(c.node_id, "big")
        for c in contacts
    ]
    assert distances == sorted(distances)


async def test_ping_over_secure_handshake(lab: Lab) -> None:
    node = lab.node(1)
    contact = lab.node(0).peers.local_contact
    assert await node.rpc.ping(contact) is True


async def test_each_node_learns_contacts(lab: Lab) -> None:
    assert await lab.wait_tables(1, timeout=5.0)
    assert all(len(node.table) >= 1 for node in lab.live_nodes())


async def test_lookup_of_unknown_identifier_terminates(lab: Lab) -> None:
    """Поиск несуществующего идентификатора завершается, а не зацикливается."""
    initiator = lab.node(0)
    unknown = bytes([0xFF]) * 32
    result = await initiator.lookup_node(unknown)
    assert result.contacts
    assert result.converged
    assert result.iterations <= initiator.config.lookup_max_iterations


async def test_ring_bootstrap_scheme(tmp_path) -> None:
    stand = make_lab(tmp_path, LabParams(n=6, scheme="ring"))
    await stand.start()
    try:
        assert await stand.wait_tables(1, timeout=5.0)
        initiator = stand.node(5)
        target = stand.node(2)
        stand.hide_contact(5, 2)
        result = await initiator.lookup_node(target.node_id)
        assert target.node_id in result.contact_ids
    finally:
        await stand.stop()


async def test_lookup_after_seed_stopped(tmp_path) -> None:
    """После остановки bootstrap-узла ранее присоединившиеся узлы работают."""
    stand = make_lab(tmp_path, LabParams(n=6))
    await stand.start()
    try:
        assert await stand.wait_tables(2, timeout=5.0)
        await stand.stop_node(0)
        initiator = stand.node(5)
        target = stand.node(3)
        stand.hide_contact(5, 3)
        result = await initiator.lookup_node(target.node_id)
        assert target.node_id in result.contact_ids
    finally:
        await stand.stop()
