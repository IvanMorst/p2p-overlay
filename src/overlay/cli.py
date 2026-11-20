"""Консольный интерфейс узла.

Команды делятся на две группы:

* ``run`` — запускает долгоживущий узел (транспорт, DHT, фоновые задачи,
  локальный интерфейс управления);
* остальные команды — обращаются к уже запущенному узлу через локальный
  интерфейс управления и печатают результат в JSON. Второй узел с тем же
  ``NodeID`` не поднимается, поэтому состояние и метрики остаются
  согласованными.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import signal
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import NodeConfig, PeerAddress
from .control import ControlClient, ControlError
from .errors import OverlayError
from .identity import Identity
from .node import Node
from .security.pki import create_ca, issue_node_certificate
from .transport.frame import short_node_id

log = logging.getLogger(__name__)


# --------------------------------------------------------------------- helpers


def _load_config(path: str | Path | None) -> NodeConfig:
    if path is None:
        return NodeConfig()
    return NodeConfig.load(path)


def _control_address(args: argparse.Namespace, config: NodeConfig) -> tuple[str, int]:
    if args.control:
        address = PeerAddress.parse(args.control)
        return address.host, address.port
    if not config.control_port:
        raise ControlError(
            "control interface is disabled: set [control] port in the config "
            "or pass --control host:port"
        )
    return config.control_host, config.control_port


async def _call(args: argparse.Namespace, command: str, **kwargs: Any) -> dict[str, Any]:
    config = _load_config(args.config)
    host, port = _control_address(args, config)
    try:
        async with await ControlClient.connect(host, port) as client:
            return await client.request(command, **kwargs)
    except (OSError, ConnectionError) as e:
        raise ControlError(f"node is not reachable at {host}:{port}: {e}") from e


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _write_json(path: str | None, payload: dict[str, Any]) -> None:
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                      encoding="utf-8")


# -------------------------------------------------------------------- commands


async def _cmd_run(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    if args.port is not None:
        config = _replace(config, listen_port=args.port)
    node = Node(config)
    await node.start(background=not args.no_background)
    report = await node.join()
    state = node.get_network_state()
    print(
        json.dumps(
            {
                "node_id": state["node_id"],
                "address": state["address"],
                "listen_port": node.bound_port,
                "control_port": node.control.port if node.control else 0,
                "security": state["security"],
                "bootstrap": report.to_dict(),
                "contacts": state["routing"]["total_contacts"],
            },
            indent=2,
            ensure_ascii=False,
        ),
        flush=True,
    )
    stop_event = asyncio.Event()

    def _request_stop(*_: object) -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    with contextlib.suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGINT, _request_stop)
        loop.add_signal_handler(signal.SIGTERM, _request_stop)
    try:
        await stop_event.wait()
    finally:
        await node.stop()
    return 0


async def _cmd_info(args: argparse.Namespace) -> int:
    response = await _call(args, "info")
    if args.json:
        _write_json(args.json, response)
    if args.brief:
        state = response
        print(f"node_id      {state['node_id']}")
        print(f"address      {state['address']}")
        print(f"security     {state['security']}")
        print(f"contacts     {state['routing']['total_contacts']} "
              f"(buckets: {state['routing']['occupied_buckets']}/"
              f"{state['routing']['buckets']})")
        print(f"rpc          {state['rpc']}")
    else:
        _print_json(response)
    return 0


async def _cmd_table(args: argparse.Namespace) -> int:
    response = await _call(args, "table")
    _write_json(args.json, response)
    if args.full:
        _print_json(response)
        return 0
    stats = response["stats"]
    print(f"k={stats['k']} id_bits={stats['id_bits']} contacts={stats['total_contacts']}")
    print(f"occupied buckets: {stats['occupied_buckets']} "
          f"full: {stats['full_buckets']} max fill: {stats['max_bucket_fill']}")
    for bucket in response["buckets"]:
        if not bucket["size"]:
            continue
        ids = ", ".join(entry["node_id"][:12] for entry in bucket["contacts"])
        print(f"  bucket {bucket['index']:>3} [{bucket['size']}/{bucket['capacity']}]: {ids}")
    return 0


async def _cmd_contacts(args: argparse.Namespace) -> int:
    response = await _call(args, "contacts")
    _write_json(args.json, response)
    for contact in response["contacts"]:
        print(f"{contact['node_id'][:12]}  {contact['address']:<24} "
              f"seen={contact['last_seen']}")
    return 0


async def _cmd_lookup(args: argparse.Namespace) -> int:
    response = await _call(args, "lookup", node_id=args.node)
    lookup = response["lookup"]
    _write_json(args.json, response)
    print(
        f"lookup {lookup['lookup_id'][:8]} target={lookup['target'][:12]} "
        f"iterations={lookup['iterations']} rpc={lookup['rpc_count']} "
        f"timeouts={lookup['timeouts']} duration={lookup['duration_s']:.4f}s"
    )
    if lookup["value_found"]:
        print(f"  value found at {lookup['value_node'][:12]}")
    for node in lookup["result_contacts"]:
        marker = " <- target" if node == lookup["target"] else ""
        print(f"  closest {node[:12]}{marker}")
    return 0


async def _cmd_ping(args: argparse.Namespace) -> int:
    response = await _call(args, "ping", node_id=args.node)
    print(f"alive={response['alive']} node={response['node_id'][:12]}")
    return 0 if response["alive"] else 1


async def _cmd_put(args: argparse.Namespace) -> int:
    response = await _call(args, "put")
    publish = response["publish"]
    _write_json(args.json, response)
    print(
        f"published key={publish['record_key'][:12]} sequence={publish['sequence_number']} "
        f"acks={publish['acks']} success={publish['success']} "
        f"duration={publish['duration_s']:.4f}s"
    )
    return 0 if publish["success"] else 1


async def _cmd_get(args: argparse.Namespace) -> int:
    response = await _call(args, "get", node_id=args.node)
    record = response["record"]
    _write_json(args.json, response)
    print(
        f"node {record['node_id'][:12]} addresses={','.join(record['addresses'])} "
        f"sequence={record['sequence_number']} ttl_left={record['ttl_left_s']}s"
    )
    return 0


async def _cmd_records(args: argparse.Namespace) -> int:
    response = await _call(args, "records")
    _write_json(args.json, response)
    stats = response["stats"]
    print(
        f"records={stats['records']} accepted={stats['accepted']} "
        f"rejected={stats['rejected']} expired={stats['expired']}"
    )
    for record in response["records"]:
        addresses = ",".join(record["addresses"])
        print(
            f"  {record['node_id'][:12]} seq={record['sequence_number']:<4} "
            f"ttl_left={record['ttl_left_s']:>7}s {addresses}"
        )
    return 0


async def _cmd_pki_init(args: argparse.Namespace) -> int:
    bundle = create_ca(args.out)
    print(f"CA certificate: {bundle.cert_path}")
    print(f"CA private key: {bundle.key_path}")
    print(
        "укажите оба пути в [security] ca_cert / ca_key каждой конфигурации узла",
        file=sys.stderr,
    )
    return 0


async def _cmd_pki_issue(args: argparse.Namespace) -> int:
    config = _load_config(args.config)
    if config.security_mode != "tls13":
        print("error: [security] mode is not tls13", file=sys.stderr)
        return 1
    ca_cert = Path(args.ca_cert) if args.ca_cert else config.ca_cert
    ca_key = Path(args.ca_key) if args.ca_key else config.ca_key
    if ca_cert is None or ca_key is None:
        print("error: CA certificate and key are required", file=sys.stderr)
        return 1
    identity = Identity.load_or_create(config.identity_dir, config.node_id_bits)
    bundle = issue_node_certificate(
        identity,
        ca_cert,
        ca_key,
        config.identity_dir,
        lifetime_days=config.certificate_lifetime_days,
    )
    print(f"node certificate: {bundle.cert_path}")
    print(f"node key: {bundle.key_path}")
    print(f"node id: {identity.node_id.hex()}")
    return 0


# ------------------------------------------------------------------ entrypoint


def _replace(config: NodeConfig, **changes: Any) -> NodeConfig:
    return replace(config, **changes)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="overlay",
        description="Узел защищённой оверлейной сети на основе Kademlia DHT",
    )
    parser.add_argument("--log-level", default="INFO", help="уровень журналирования")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser, *, config_required: bool = True) -> None:
        p.add_argument("--config", type=Path, required=config_required,
                       help="путь к TOML-конфигурации узла")
        p.add_argument("--control", default=None,
                       help="адрес локального интерфейса управления host:port")

    p_run = sub.add_parser("run", help="запустить узел")
    common(p_run)
    p_run.add_argument("--port", type=int, default=None, help="переопределить listen_port")
    p_run.add_argument("--no-background", action="store_true",
                       help="не запускать refresh и обслуживание записей")
    p_run.set_defaults(func=_cmd_run)

    p_info = sub.add_parser("info", help="состояние узла")
    common(p_info)
    p_info.add_argument("--json", default=None)
    p_info.add_argument("--brief", action="store_true")
    p_info.set_defaults(func=_cmd_info)

    p_table = sub.add_parser("table", help="содержимое k-bucket")
    common(p_table)
    p_table.add_argument("--json", default=None)
    p_table.add_argument("--full", action="store_true")
    p_table.set_defaults(func=_cmd_table)

    p_contacts = sub.add_parser("contacts", help="контакты таблицы маршрутизации")
    common(p_contacts)
    p_contacts.add_argument("--json", default=None)
    p_contacts.set_defaults(func=_cmd_contacts)

    p_lookup = sub.add_parser("lookup", help="итеративный поиск узла")
    common(p_lookup)
    p_lookup.add_argument("--node", required=True, help="NodeID в hex")
    p_lookup.add_argument("--json", default=None, help="сохранить трассу в файл")
    p_lookup.set_defaults(func=_cmd_lookup)

    p_ping = sub.add_parser("ping", help="проверить доступность контакта")
    common(p_ping)
    p_ping.add_argument("--node", required=True, help="NodeID в hex")
    p_ping.set_defaults(func=_cmd_ping)

    p_put = sub.add_parser("put", help="опубликовать собственную адресную запись")
    common(p_put)
    p_put.add_argument("--json", default=None)
    p_put.set_defaults(func=_cmd_put)

    p_get = sub.add_parser("get", help="найти адресную запись по NodeID")
    common(p_get)
    p_get.add_argument("--node", required=True, help="NodeID в hex")
    p_get.add_argument("--json", default=None)
    p_get.set_defaults(func=_cmd_get)

    p_records = sub.add_parser("records", help="локальное хранилище записей DHT")
    common(p_records)
    p_records.add_argument("--json", default=None)
    p_records.set_defaults(func=_cmd_records)

    p_pki = sub.add_parser("pki", help="инфраструктура сертификатов стенда")
    pki_sub = p_pki.add_subparsers(dest="pki_cmd", required=True)

    p_init = pki_sub.add_parser("init", help="создать корневой сертификат стенда")
    p_init.add_argument("--out", type=Path, required=True, help="каталог для ca.pem и ca-key.pem")
    p_init.set_defaults(func=_cmd_pki_init)

    p_issue = pki_sub.add_parser("issue", help="выпустить сертификат узла")
    p_issue.add_argument("--config", type=Path, required=True, help="конфигурация узла")
    p_issue.add_argument("--ca-cert", default=None)
    p_issue.add_argument("--ca-key", default=None)
    p_issue.set_defaults(func=_cmd_pki_issue)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        code = asyncio.run(args.func(args))
    except KeyboardInterrupt:
        code = 130
    except (OverlayError, ControlError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


__all__ = ["build_parser", "main", "short_node_id"]
