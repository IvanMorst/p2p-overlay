"""Тесты конфигурации: значения по умолчанию, TOML, валидация, manifest."""

from __future__ import annotations

from pathlib import Path

import pytest

from overlay.config import ConfigError, NodeConfig, PeerAddress


def test_defaults_match_short_level() -> None:
    config = NodeConfig()
    assert config.k_bucket_size == 3
    assert config.alpha == 3
    assert config.replication_factor == 3
    assert config.store_success_acks == 2
    assert config.node_id_bits == 256
    assert 120 <= config.record_ttl_seconds <= 300
    assert config.republish_fraction <= 0.5
    assert config.tunnel_min_relays >= 2
    assert config.allow_direct_fallback is False


def test_republish_interval_is_at_most_half_ttl() -> None:
    config = NodeConfig(record_ttl_seconds=200, republish_fraction=0.5)
    assert config.republish_interval_seconds <= config.record_ttl_seconds / 2


def test_load_toml(tmp_path: Path) -> None:
    path = tmp_path / "node.toml"
    path.write_text(
        """
[node]
node_id_bits = 128
state_dir = "state-node1"

[network]
listen_host = "127.0.0.1"
listen_port = 7100
bootstrap_peers = ["127.0.0.1:7000", "127.0.0.1:7001"]

[dht]
k_bucket_size = 2
alpha = 2
replication_factor = 3
record_ttl_seconds = 150

[control]
port = 9100
""",
        encoding="utf-8",
    )
    config = NodeConfig.load(path)
    assert config.node_id_bits == 128
    assert config.listen_port == 7100
    assert config.k_bucket_size == 2
    assert config.alpha == 2
    assert config.record_ttl_seconds == 150
    assert config.control_port == 9100
    assert [str(p) for p in config.bootstrap_peers] == ["127.0.0.1:7000", "127.0.0.1:7001"]
    # Относительный state_dir разрешается относительно файла конфигурации.
    assert config.state_dir == (tmp_path / "state-node1").resolve()


def test_validation_rejects_bad_values() -> None:
    with pytest.raises(ConfigError):
        NodeConfig(node_id_bits=100).validate()
    with pytest.raises(ConfigError):
        NodeConfig(k_bucket_size=0).validate()
    with pytest.raises(ConfigError):
        NodeConfig(alpha=0).validate()
    with pytest.raises(ConfigError):
        NodeConfig(store_success_acks=5).validate()
    with pytest.raises(ConfigError):
        NodeConfig(republish_fraction=0.9).validate()
    with pytest.raises(ConfigError):
        NodeConfig(tunnel_min_relays=4, tunnel_max_relays=3).validate()
    with pytest.raises(ConfigError):
        NodeConfig(security_mode="none").validate()


def test_peer_address_parsing() -> None:
    assert str(PeerAddress.parse("127.0.0.1:7000")) == "127.0.0.1:7000"
    assert PeerAddress.parse("[::1]:7000").host == "::1"
    with pytest.raises(ConfigError):
        PeerAddress.parse("127.0.0.1")
    with pytest.raises(ConfigError):
        PeerAddress.parse("127.0.0.1:0")


def test_manifest_contains_experiment_metadata(tmp_path: Path) -> None:
    config = NodeConfig(state_dir=tmp_path, metrics_dir=tmp_path / "results")
    manifest = config.to_manifest()
    for key in (
        "node_id_bits",
        "k_bucket_size",
        "alpha",
        "replication_factor",
        "record_ttl_seconds",
        "refresh_interval_seconds",
        "bootstrap_peers",
        "random_seed",
        "security_mode",
        "tunnel_min_relays",
    ):
        assert key in manifest


def test_unknown_sections_are_kept_as_extras() -> None:
    config = NodeConfig.from_dict({"lab": {"note": "demo"}})
    assert config.extras["lab"]["note"] == "demo"
