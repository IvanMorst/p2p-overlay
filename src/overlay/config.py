from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class NodeConfig:
    node_id_bits: int = 160
    k_bucket_size: int = 3
    alpha: int = 3
    replication_factor: int = 3
    listen_host: str = "0.0.0.0"
    listen_port: int = 7000
    state_dir: Path = Path("./state")
    record_ttl_seconds: int = 180
    refresh_interval_seconds: int = 60
    republish_fraction: float = 0.5
    connect_timeout_seconds: float = 5.0
    request_timeout_seconds: float = 5.0
    max_frame_payload: int = 65536
    bootstrap_peers: list[str] | None = None

    @staticmethod
    def load(path: str | Path) -> "NodeConfig":
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        node = data.get("node", {})
        net = data.get("network", {})
        dht = data.get("dht", {})
        return NodeConfig(
            node_id_bits=node.get("node_id_bits", 160),
            k_bucket_size=dht.get("k_bucket_size", 3),
            alpha=dht.get("alpha", 3),
            replication_factor=dht.get("replication_factor", 3),
            listen_host=net.get("listen_host", "0.0.0.0"),
            listen_port=net.get("listen_port", 7000),
            state_dir=Path(node.get("state_dir", "./state")),
            record_ttl_seconds=dht.get("record_ttl_seconds", 180),
            refresh_interval_seconds=dht.get("refresh_interval_seconds", 60),
            republish_fraction=dht.get("republish_fraction", 0.5),
            connect_timeout_seconds=net.get("connect_timeout_seconds", 5.0),
            request_timeout_seconds=net.get("request_timeout_seconds", 5.0),
            max_frame_payload=net.get("max_frame_payload", 65536),
            bootstrap_peers=net.get("bootstrap_peers"),
        )