"""Тестовый стенд: набор узлов в одном процессе asyncio.

Стенд не является частью продукта: он создаёт независимые узлы с раздельными
каталогами состояния, портами, таблицами маршрутизации и журналами, как того
требует раздел 14 ТЗ, и применяет выбранную bootstrap-схему.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from overlay.config import NodeConfig, PeerAddress
from overlay.node import Node


@dataclass(slots=True)
class LabParams:
    """Параметры тестового стенда."""

    n: int = 5
    k: int = 3
    alpha: int = 3
    replication_factor: int = 3
    node_id_bits: int = 256
    security_mode: str = "plain"
    scheme: str = "star"
    request_timeout: float = 3.0
    connect_timeout: float = 3.0
    record_ttl_seconds: int = 180
    refresh_interval_seconds: int = 3600
    metrics: bool = False
    tunnel_min_relays: int = 2
    tunnel_max_relays: int = 3
    allow_direct_fallback: bool = False


@dataclass(slots=True)
class Lab:
    """Набор узлов и операции над ним."""

    tmp: Path
    params: LabParams = field(default_factory=LabParams)
    nodes: list[Node] = field(default_factory=list)
    active: set[int] = field(default_factory=set)

    # ------------------------------------------------------------- creation

    def config(self, index: int, *, port: int = 0, **overrides: object) -> NodeConfig:
        base = NodeConfig(
            node_id_bits=self.params.node_id_bits,
            state_dir=self.tmp / f"node{index}",
            listen_host="127.0.0.1",
            listen_port=port,
            security_mode=self.params.security_mode,
            k_bucket_size=self.params.k,
            alpha=self.params.alpha,
            replication_factor=self.params.replication_factor,
            request_timeout_seconds=self.params.request_timeout,
            connect_timeout_seconds=self.params.connect_timeout,
            record_ttl_seconds=self.params.record_ttl_seconds,
            refresh_interval_seconds=self.params.refresh_interval_seconds,
            metrics_enabled=self.params.metrics,
            metrics_dir=self.tmp / "results",
            metrics_run_id="test",
            tunnel_min_relays=self.params.tunnel_min_relays,
            tunnel_max_relays=self.params.tunnel_max_relays,
            allow_direct_fallback=self.params.allow_direct_fallback,
        )
        config = replace(base, **overrides) if overrides else base
        config.validate()
        return config

    async def start_node(self, index: int, *, port: int = 0, **overrides: object) -> Node:
        node = Node(self.config(index, port=port, **overrides))
        await node.start()
        if index < len(self.nodes):
            self.nodes[index] = node
        else:
            self.nodes.append(node)
        self.active.add(index)
        return node

    async def start(self, *, join: bool = True) -> Lab:
        for index in range(self.params.n):
            await self.start_node(index)
        if join:
            await self.bootstrap()
        return self

    # ------------------------------------------------------------ bootstrap

    @property
    def seed(self) -> Node:
        return self.nodes[0]

    def peer_of(self, index: int) -> PeerAddress:
        node = self.nodes[index]
        return PeerAddress("127.0.0.1", node.bound_port)

    async def bootstrap(self, scheme: str | None = None) -> None:
        scheme = scheme or self.params.scheme
        if scheme == "star":
            for index in range(1, len(self.nodes)):
                await self.join(index, 0)
        elif scheme == "ring":
            for index in range(1, len(self.nodes)):
                await self.join(index, index - 1)
        elif scheme == "tree":
            for index in range(1, len(self.nodes)):
                await self.join(index, (index - 1) // 2)
        elif scheme == "multi-seed":
            seeds = [i for i in range(len(self.nodes)) if i < 3]
            for index in range(3, len(self.nodes)):
                for seed in seeds:
                    await self.join(index, seed)
        else:
            raise ValueError(f"unknown bootstrap scheme: {scheme}")

    async def join(self, index: int, peer_index: int) -> dict[str, object]:
        report = await self.nodes[index].join([self.peer_of(peer_index)])
        await asyncio.sleep(0)
        return report.to_dict()

    async def join_many(self, index: int, peer_indexes: Sequence[int]) -> dict[str, object]:
        peers = [self.peer_of(i) for i in peer_indexes]
        report = await self.nodes[index].join(peers)
        return report.to_dict()

    # ------------------------------------------------------------- teardown

    async def stop_node(self, index: int) -> None:
        if index in self.active:
            await self.nodes[index].stop()
            self.active.discard(index)

    async def stop(self) -> None:
        for index in list(self.active):
            with contextlib.suppress(Exception):
                await self.nodes[index].stop()
        self.active.clear()

    async def __aenter__(self) -> Lab:
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # -------------------------------------------------------------- helpers

    def live_nodes(self) -> list[Node]:
        return [self.nodes[i] for i in sorted(self.active)]

    def node(self, index: int) -> Node:
        return self.nodes[index]

    def hide_contact(self, initiator: int, target: int) -> bool:
        """Удалить контакт цели из таблицы инициатора (имитация холодного старта)."""
        node = self.nodes[initiator]
        target_id = self.nodes[target].node_id
        removed = node.table.remove(target_id)
        node.peers.forget(target_id)
        return removed

    def table_sizes(self) -> list[int]:
        return [len(node.table) for i, node in enumerate(self.nodes) if i in self.active]

    async def wait_tables(self, minimum: int, *, timeout: float = 10.0) -> bool:
        """Дождаться, пока у всех живых узлов будет не менее ``minimum`` контактов."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(len(node.table) >= minimum for node in self.live_nodes()):
                return True
            await asyncio.sleep(0.05)
        return False

    async def converge(
        self, *, rounds: int = 2, threshold: float = 0.95, per_round: int = 10
    ) -> float:
        """Выполнить контрольные поиски и вернуть долю успешных в последнем раунде."""
        rate = 0.0
        for _ in range(rounds):
            successes = 0
            attempts = 0
            for initiator, target in self._pairs(per_round):
                self.hide_contact(initiator, target)
                result = await self.nodes[initiator].lookup_node(self.nodes[target].node_id)
                attempts += 1
                if self.nodes[target].node_id in result.contact_ids:
                    successes += 1
            rate = successes / attempts if attempts else 0.0
            if rate < threshold:
                return rate
        return rate

    def _pairs(self, count: int) -> list[tuple[int, int]]:
        live = sorted(self.active)
        if len(live) < 2:
            return []
        pairs: list[tuple[int, int]] = []
        for step in range(count):
            initiator = live[step % len(live)]
            target = live[(step * 3 + 1) % len(live)]
            if initiator == target:
                target = live[(live.index(initiator) + 1) % len(live)]
            pairs.append((initiator, target))
        return pairs

    def snapshot_tables(self) -> dict[int, list[dict[str, object]]]:
        return {i: self.nodes[i].table.bucket_table() for i in sorted(self.active)}


def make_lab(tmp: Path, params: LabParams | None = None) -> Lab:
    return Lab(tmp=tmp, params=params or LabParams())


async def start_lab(tmp: Path, params: LabParams | None = None) -> Lab:
    return await make_lab(tmp, params).start()


def contact_ids(nodes: Iterable[Node]) -> list[bytes]:
    return [node.node_id for node in nodes]
