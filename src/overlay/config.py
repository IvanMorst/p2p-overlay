"""Конфигурация узла: загрузка TOML, валидация, манифест прогона.

Все параметры, перечисленные в разделе 14 ТЗ, выносятся в конфигурацию и не
требуют правки исходного кода.
"""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .errors import OverlayError


class ConfigError(OverlayError):
    """Некорректная конфигурация."""


@dataclass(frozen=True, slots=True)
class PeerAddress:
    """Адрес известного узла (bootstrap-контакт)."""

    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"

    @classmethod
    def parse(cls, value: str) -> PeerAddress:
        text = value.strip()
        if not text:
            raise ConfigError("empty peer address")
        if text.startswith("["):
            host, _, rest = text[1:].partition("]")
            if not rest.startswith(":"):
                raise ConfigError(f"malformed peer address: {value!r}")
            port_text = rest[1:]
        else:
            host, sep, port_text = text.rpartition(":")
            if not sep:
                raise ConfigError(f"peer address must be host:port, got {value!r}")
        try:
            port = int(port_text)
        except ValueError as e:
            raise ConfigError(f"invalid port in {value!r}") from e
        if not 1 <= port <= 65_535:
            raise ConfigError(f"port out of range in {value!r}")
        if not host:
            raise ConfigError(f"empty host in {value!r}")
        return cls(host=host, port=port)


@dataclass(frozen=True, slots=True)
class NodeConfig:
    # --- идентичность и состояние -----------------------------------------
    node_id_bits: int = 256
    state_dir: Path = Path("./state")
    random_seed: int = 0

    # --- сеть --------------------------------------------------------------
    listen_host: str = "0.0.0.0"
    listen_port: int = 7000
    advertise_host: str = ""
    connect_timeout_seconds: float = 5.0
    request_timeout_seconds: float = 5.0
    handshake_timeout_seconds: float = 10.0
    max_frame_payload: int = 65_536
    bootstrap_peers: tuple[PeerAddress, ...] = ()

    # --- DHT ---------------------------------------------------------------
    k_bucket_size: int = 3
    alpha: int = 3
    replication_factor: int = 3
    store_success_acks: int = 2
    record_ttl_seconds: int = 180
    refresh_interval_seconds: int = 60
    republish_fraction: float = 0.5
    max_record_bytes: int = 4096
    max_addresses: int = 4
    lookup_max_iterations: int = 32
    bucket_refresh_interval_seconds: float = 600.0

    # --- защита канала -----------------------------------------------------
    security_mode: str = "tls13"
    tls_min_version: str = "TLSv1.3"
    ca_cert: Path | None = None
    ca_key: Path | None = None
    cert_file: Path | None = None
    key_file: Path | None = None
    verify_peer_identity: bool = True
    allow_bootstrap_trust: bool = True
    certificate_lifetime_days: int = 365
    replay_cache_size: int = 4096

    # --- туннели -----------------------------------------------------------
    tunnel_min_relays: int = 2
    tunnel_max_relays: int = 3
    tunnel_max_hops: int = 5
    tunnel_pool_size: int = 1
    tunnel_build_timeout_seconds: float = 10.0
    tunnel_data_timeout_seconds: float = 5.0
    tunnel_health_interval_seconds: float = 2.0
    tunnel_max_retries: int = 3
    allow_direct_fallback: bool = False

    # --- приложение --------------------------------------------------------
    max_message_bytes: int = 8192
    history_size: int = 200

    # --- локальный интерфейс управления ------------------------------------
    control_host: str = "127.0.0.1"
    control_port: int = 0

    # --- метрики -----------------------------------------------------------
    metrics_enabled: bool = True
    metrics_dir: Path = Path("./results")
    metrics_run_id: str = "run"

    extras: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ load

    @staticmethod
    def load(path: str | Path) -> NodeConfig:
        # utf-8-sig: редакторы Windows могут сохранять файл с BOM.
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8-sig"))
        return NodeConfig.from_dict(raw, base_dir=Path(path).parent)

    @staticmethod
    def from_dict(data: dict[str, Any], *, base_dir: Path | None = None) -> NodeConfig:
        node = _section(data, "node")
        net = _section(data, "network")
        dht = _section(data, "dht")
        sec = _section(data, "security")
        tun = _section(data, "tunnel")
        app = _section(data, "app")
        met = _section(data, "metrics")
        ctl = _section(data, "control")

        state_dir = Path(str(node.get("state_dir", "./state")))
        metrics_dir = Path(str(met.get("dir", "./results")))
        if base_dir is not None:
            state_dir = _resolve(state_dir, base_dir)
            metrics_dir = _resolve(metrics_dir, base_dir)

        peers_raw = net.get("bootstrap_peers", []) or []
        peers: list[PeerAddress] = []
        for item in peers_raw:
            peers.append(item if isinstance(item, PeerAddress) else PeerAddress.parse(str(item)))

        cfg = NodeConfig(
            node_id_bits=int(node.get("node_id_bits", 256)),
            state_dir=state_dir,
            random_seed=int(node.get("random_seed", 0)),
            listen_host=str(net.get("listen_host", "0.0.0.0")),
            listen_port=int(net.get("listen_port", 7000)),
            advertise_host=str(net.get("advertise_host", "")),
            connect_timeout_seconds=float(net.get("connect_timeout_seconds", 5.0)),
            request_timeout_seconds=float(net.get("request_timeout_seconds", 5.0)),
            handshake_timeout_seconds=float(net.get("handshake_timeout_seconds", 10.0)),
            max_frame_payload=int(net.get("max_frame_payload", 65_536)),
            bootstrap_peers=tuple(peers),
            k_bucket_size=int(dht.get("k_bucket_size", 3)),
            alpha=int(dht.get("alpha", 3)),
            replication_factor=int(dht.get("replication_factor", 3)),
            store_success_acks=int(dht.get("store_success_acks", 2)),
            record_ttl_seconds=int(dht.get("record_ttl_seconds", 180)),
            refresh_interval_seconds=int(dht.get("refresh_interval_seconds", 60)),
            republish_fraction=float(dht.get("republish_fraction", 0.5)),
            max_record_bytes=int(dht.get("max_record_bytes", 4096)),
            max_addresses=int(dht.get("max_addresses", 4)),
            lookup_max_iterations=int(dht.get("lookup_max_iterations", 32)),
            bucket_refresh_interval_seconds=float(
                dht.get("bucket_refresh_interval_seconds", 600.0)
            ),
            security_mode=str(sec.get("mode", "tls13")),
            tls_min_version=str(sec.get("tls_min_version", "TLSv1.3")),
            ca_cert=_optional_path(sec.get("ca_cert"), base_dir),
            ca_key=_optional_path(sec.get("ca_key"), base_dir),
            cert_file=_optional_path(sec.get("cert_file"), base_dir),
            key_file=_optional_path(sec.get("key_file"), base_dir),
            verify_peer_identity=bool(sec.get("verify_peer_identity", True)),
            allow_bootstrap_trust=bool(sec.get("allow_bootstrap_trust", True)),
            certificate_lifetime_days=int(sec.get("certificate_lifetime_days", 365)),
            replay_cache_size=int(sec.get("replay_cache_size", 4096)),
            tunnel_min_relays=int(tun.get("min_relays", 2)),
            tunnel_max_relays=int(tun.get("max_relays", 3)),
            tunnel_max_hops=int(tun.get("max_hops", 5)),
            tunnel_pool_size=int(tun.get("pool_size", 1)),
            tunnel_build_timeout_seconds=float(tun.get("build_timeout_seconds", 10.0)),
            tunnel_data_timeout_seconds=float(tun.get("data_timeout_seconds", 5.0)),
            tunnel_health_interval_seconds=float(tun.get("health_interval_seconds", 2.0)),
            tunnel_max_retries=int(tun.get("max_retries", 3)),
            allow_direct_fallback=bool(tun.get("allow_direct_fallback", False)),
            max_message_bytes=int(app.get("max_message_bytes", 8192)),
            history_size=int(app.get("history_size", 200)),
            control_host=str(ctl.get("host", "127.0.0.1")),
            control_port=int(ctl.get("port", 0)),
            metrics_enabled=bool(met.get("enabled", True)),
            metrics_dir=metrics_dir,
            metrics_run_id=str(met.get("run_id", "run")),
            extras={k: v for k, v in data.items() if k not in _KNOWN_SECTIONS},
        )
        cfg.validate()
        return cfg

    # -------------------------------------------------------------- validate

    def validate(self) -> None:
        if not 8 <= self.node_id_bits <= 256 or self.node_id_bits % 8 != 0:
            raise ConfigError("node_id_bits must be a multiple of 8 in [8, 256]")
        if not 0 <= self.listen_port <= 65_535:
            raise ConfigError("listen_port out of range")
        if not 0 <= self.control_port <= 65_535:
            raise ConfigError("control_port out of range")
        if self.k_bucket_size < 1:
            raise ConfigError("k_bucket_size must be >= 1")
        if self.alpha < 1:
            raise ConfigError("alpha must be >= 1")
        if self.replication_factor < 1:
            raise ConfigError("replication_factor must be >= 1")
        if not 1 <= self.store_success_acks <= self.replication_factor:
            raise ConfigError("store_success_acks must be in [1, replication_factor]")
        if self.record_ttl_seconds < 10:
            raise ConfigError("record_ttl_seconds must be >= 10")
        if not 0 < self.republish_fraction <= 0.5:
            raise ConfigError("republish_fraction must be in (0, 0.5]")
        if self.refresh_interval_seconds <= 0:
            raise ConfigError("refresh_interval_seconds must be > 0")
        if self.max_frame_payload > 65_536:
            raise ConfigError("max_frame_payload must be <= 65536")
        if self.max_message_bytes > self.max_frame_payload:
            raise ConfigError("max_message_bytes exceeds max_frame_payload")
        if self.security_mode not in {"tls13", "plain"}:
            raise ConfigError("security mode must be 'tls13' or 'plain'")
        if self.tunnel_min_relays < 1:
            raise ConfigError("tunnel min_relays must be >= 1")
        if self.tunnel_max_relays < self.tunnel_min_relays:
            raise ConfigError("tunnel max_relays must be >= min_relays")
        if self.tunnel_max_hops < self.tunnel_min_relays + 1:
            raise ConfigError("tunnel max_hops must exceed min_relays")
        if self.tunnel_pool_size < 1:
            raise ConfigError("tunnel pool_size must be >= 1")

    # ------------------------------------------------------------- accessors

    @property
    def node_id_bytes(self) -> int:
        return self.node_id_bits // 8

    @property
    def id_space_bits(self) -> int:
        return self.node_id_bits

    @property
    def republish_interval_seconds(self) -> float:
        return self.record_ttl_seconds * self.republish_fraction

    @property
    def identity_dir(self) -> Path:
        return self.state_dir / "identity"

    @property
    def storage_path(self) -> Path:
        return self.state_dir / "dht.cbor"

    def to_manifest(self) -> dict[str, Any]:
        """Машиночитаемое описание конфигурации для manifest прогона."""
        data = asdict(self)
        data["state_dir"] = str(self.state_dir)
        data["metrics_dir"] = str(self.metrics_dir)
        data["ca_cert"] = str(self.ca_cert) if self.ca_cert else None
        data["ca_key"] = str(self.ca_key) if self.ca_key else None
        data["cert_file"] = str(self.cert_file) if self.cert_file else None
        data["key_file"] = str(self.key_file) if self.key_file else None
        data["bootstrap_peers"] = [str(p) for p in self.bootstrap_peers]
        data["republish_interval_seconds"] = self.republish_interval_seconds
        return data


_KNOWN_SECTIONS = {"node", "network", "dht", "security", "tunnel", "app", "metrics", "control"}


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"section [{name}] must be a table")
    return value


def _resolve(path: Path, base_dir: Path) -> Path:
    return path if path.is_absolute() else (base_dir / path).resolve()


def _optional_path(value: Any, base_dir: Path | None) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(str(value))
    if base_dir is None:
        return path
    return _resolve(path, base_dir)


DEFAULT_CONFIG = NodeConfig()
