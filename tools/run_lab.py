"""Однокомандный запуск стенда из N логических узлов.

Скрипт создаёт корневой сертификат стенда, генерирует по конфигурации на
каждый узел, запускает независимые процессы ``overlay run``, ждёт готовности и
(по флагу ``--send``) проверяет доставку сообщения через туннель.

Примеры:

    python tools/run_lab.py --nodes 13 --scheme star
    python tools/run_lab.py --nodes 4 --scheme ring --send --duration 30
    python tools/run_lab.py --nodes 6 --scheme tree --base-port 7100 --control-base 9100

Каталог прогона содержит ``pki/``, ``configs/``, ``state/``, ``results/`` и
``manifest.json`` с параметрами запуска.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from overlay.control import ControlClient  # noqa: E402
from overlay.security.pki import create_ca  # noqa: E402

CONFIG_TEMPLATE = """\
[node]
node_id_bits = {node_id_bits}
state_dir = "../state/node{i}"
random_seed = {seed}

[network]
listen_host = "127.0.0.1"
listen_port = {port}
advertise_host = "127.0.0.1"
connect_timeout_seconds = {connect_timeout}
request_timeout_seconds = {request_timeout}
handshake_timeout_seconds = 10.0
max_frame_payload = 65536
bootstrap_peers = [{peers}]

[dht]
k_bucket_size = {k}
alpha = {alpha}
replication_factor = 3
store_success_acks = 2
record_ttl_seconds = {ttl}
refresh_interval_seconds = {refresh}
republish_fraction = 0.5

[security]
mode = "tls13"
ca_cert = "../pki/ca.pem"
ca_key = "../pki/ca-key.pem"

[tunnel]
min_relays = {relays}
max_relays = {relays}
max_hops = {max_hops}
build_timeout_seconds = 10.0
data_timeout_seconds = 5.0
health_interval_seconds = 2.0

[metrics]
enabled = true
dir = "../results"
run_id = "{run_id}"

[control]
host = "127.0.0.1"
port = {control}
"""


def bootstrap_peers(index: int, scheme: str, ports: list[int]) -> list[int]:
    if index == 0:
        return []
    if scheme == "star":
        return [0]
    if scheme == "ring":
        return [index - 1]
    if scheme == "tree":
        return [(index - 1) // 2]
    if scheme == "multi-seed":
        seeds = [0, 1, 2][: min(3, index)]
        return seeds or [0]
    raise SystemExit(f"unknown scheme: {scheme}")


def write_configs(args: argparse.Namespace, run_dir: Path) -> list[Path]:
    configs_dir = run_dir / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)
    ports = [args.base_port + i for i in range(args.nodes)]
    paths: list[Path] = []
    for index in range(args.nodes):
        peers = bootstrap_peers(index, args.scheme, ports)
        peers_text = ", ".join(f'"127.0.0.1:{ports[p]}"' for p in peers)
        text = CONFIG_TEMPLATE.format(
            i=index,
            seed=args.seed + index,
            port=ports[index],
            control=args.control_base + index,
            peers=peers_text,
            node_id_bits=args.node_id_bits,
            k=args.k,
            alpha=args.alpha,
            ttl=args.ttl,
            refresh=args.refresh,
            relays=args.relays,
            max_hops=max(args.relays + 2, 5),
            connect_timeout=args.connect_timeout,
            request_timeout=args.request_timeout,
            run_id=args.run_id,
        )
        path = configs_dir / f"node{index}.toml"
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def start_nodes(configs: list[Path], run_dir: Path) -> list[subprocess.Popen[bytes]]:
    logs = run_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    processes: list[subprocess.Popen[bytes]] = []
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    for index, config in enumerate(configs):
        out = (logs / f"node{index}.out").open("wb")
        err = (logs / f"node{index}.err").open("wb")
        process = subprocess.Popen(
            [sys.executable, "-m", "overlay", "run", "--config", str(config)],
            stdout=out,
            stderr=err,
            env=env,
            cwd=str(ROOT),
        )
        processes.append(process)
    return processes


async def wait_ready(ports: list[int], *, timeout: float = 60.0) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    ready: dict[int, dict[str, Any]] = {}
    while time.monotonic() < deadline:
        for index, port in enumerate(ports):
            if index in ready:
                continue
            try:
                async with await ControlClient.connect("127.0.0.1", port) as client:
                    response = await client.request("info")
                ready[index] = response
            except Exception:
                continue
        if len(ready) == len(ports):
            break
        await asyncio.sleep(0.2)
    missing = [i for i in range(len(ports)) if i not in ready]
    if missing:
        raise SystemExit(f"nodes did not become ready: {missing}")
    return [ready[i] for i in range(len(ports))]


async def convergence(ports: list[int], *, timeout: float = 30.0) -> dict[str, Any]:
    """Дождаться, пока у всех узлов появятся контакты."""
    deadline = time.monotonic() + timeout
    stats: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        stats = []
        for port in ports:
            async with await ControlClient.connect("127.0.0.1", port) as client:
                response = await client.request("table")
            stats.append(response["stats"])
        if all(item["total_contacts"] >= 1 for item in stats):
            return {"rounds": stats[-1], "contacts": [s["total_contacts"] for s in stats]}
        await asyncio.sleep(0.3)
    return {"rounds": {}, "contacts": [s["total_contacts"] for s in stats]}


async def demo_send(ports: list[int], count: int) -> dict[str, Any]:
    """Отправить сообщение с первого узла на последний через туннель."""
    async with await ControlClient.connect("127.0.0.1", ports[-1]) as client:
        target = (await client.request("info"))["node_id"]
    async with await ControlClient.connect("127.0.0.1", ports[0]) as client:
        response = await client.request("send", node_id=target, text="лабораторное сообщение")
    return response["message"]


async def main_async(args: argparse.Namespace, run_dir: Path) -> int:
    ca = create_ca(run_dir / "pki")
    configs = write_configs(args, run_dir)
    manifest = {
        "run_id": args.run_id,
        "nodes": args.nodes,
        "scheme": args.scheme,
        "k": args.k,
        "alpha": args.alpha,
        "relays": args.relays,
        "node_id_bits": args.node_id_bits,
        "base_port": args.base_port,
        "control_base": args.control_base,
        "started_at": time.time(),
        "ca_cert": str(ca.cert_path),
        "configs": [str(path) for path in configs],
        "python": sys.version,
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"stand directory: {run_dir}")
    print(f"configs: {len(configs)}, scheme: {args.scheme}, k={args.k}, relays={args.relays}")

    processes = start_nodes(configs, run_dir)
    ports = [args.control_base + i for i in range(args.nodes)]
    try:
        states = await wait_ready(ports, timeout=args.ready_timeout)
        print(f"nodes ready: {len(states)}")
        conv = await convergence(ports, timeout=args.converge_timeout)
        print(f"contacts per node: {conv['contacts']}")

        if args.send:
            if args.nodes < args.relays + 2:
                print("not enough nodes for the requested tunnel", file=sys.stderr)
            else:
                message = await demo_send(ports, args.nodes)
                print(
                    "message:",
                    message["status"],
                    f"latency={message['latency_s']:.4f}s",
                    "hops=" + " -> ".join(message["hops"]),
                )

        results = {
            "manifest": manifest,
            "contacts": conv["contacts"],
            "ready": [state["node_id"] for state in states],
        }
        (run_dir / "summary.json").write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        if args.duration > 0:
            print(f"keeping the stand alive for {args.duration} s (Ctrl+C to stop)")
            await asyncio.sleep(args.duration)
        else:
            print("stand is running; press Ctrl+C to stop")
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                with contextlib.suppress(NotImplementedError, ValueError):
                    loop.add_signal_handler(sig, stop.set)
            await stop.wait()
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            with contextlib.suppress(Exception):
                process.wait(timeout=10)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, default=13)
    parser.add_argument("--scheme", default="star", choices=["star", "ring", "tree", "multi-seed"])
    parser.add_argument("--dir", type=Path, default=None, help="каталог прогона")
    parser.add_argument("--base-port", type=int, default=7000)
    parser.add_argument("--control-base", type=int, default=9000)
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--alpha", type=int, default=3)
    parser.add_argument("--relays", type=int, default=2)
    parser.add_argument("--node-id-bits", type=int, default=256)
    parser.add_argument("--ttl", type=int, default=180)
    parser.add_argument("--refresh", type=int, default=60)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--request-timeout", type=float, default=3.0)
    parser.add_argument("--ready-timeout", type=float, default=60.0)
    parser.add_argument("--converge-timeout", type=float, default=30.0)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--send", action="store_true", help="отправить контрольное сообщение")
    parser.add_argument("--duration", type=float, default=0.0, help="сколько секунд держать стенд")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.run_id = args.run_id or time.strftime("lab-%Y%m%d-%H%M%S")
    run_dir = (args.dir or (ROOT / "results" / args.run_id)).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    try:
        return asyncio.run(main_async(args, run_dir))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

