"""Сравнение форматов сериализации payload.

Скрипт измеряет размер закодированного представления одинаковых логических
структур в JSON, MessagePack и каноническом CBOR, а также проверяет
детерминированность кодирования (важно для подписи записей DHT).

Запуск:

    python tools/compare_codecs.py [--json report.json]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

import cbor2

try:  # MessagePack — необязательная зависимость, только для измерения
    import msgpack
except ImportError:  # pragma: no cover
    msgpack = None  # type: ignore[assignment]

SAMPLES: dict[str, Any] = {
    "ping": {"ok": True, "node_id": bytes(range(32))},
    "find_node_request": {"target": bytes(range(32)), "count": 3},
    "contact": {
        "id": bytes(range(32)),
        "key": bytes(range(44)),
        "host": "192.168.10.24",
        "port": 7000,
    },
    "find_node_response": {
        "contacts": [
            {"id": bytes(range(32)), "key": bytes(range(44)), "host": "10.0.0.1", "port": 7001}
            for _ in range(3)
        ],
        "node_id": bytes(range(32)),
        "total": 12,
    },
    "error": {"code": 8, "detail": "HELLO NodeID does not match the presented public key"},
}


def _json_bytes(value: Any) -> bytes:
    return json.dumps(_json_ready(value), separators=(",", ":"), ensure_ascii=False).encode()


def _json_ready(value: Any) -> Any:
    """JSON не поддерживает bytes: используется base64, как в реальном JSON-профиле."""
    import base64

    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {str(k): _json_ready(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_ready(v) for v in value]
    return value


def _msgpack_bytes(value: Any) -> bytes | None:
    if msgpack is None:
        return None
    return msgpack.packb(value, use_bin_type=True)


def _cbor_bytes(value: Any) -> bytes:
    return cbor2.dumps(value, canonical=True)


def measure() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for name, sample in SAMPLES.items():
        json_size = len(_json_bytes(sample))
        msgpack_size = _msgpack_bytes(sample)
        cbor_size = len(_cbor_bytes(sample))
        rows.append(
            {
                "structure": name,
                "json": json_size,
                "msgpack": len(msgpack_size) if msgpack_size is not None else None,
                "cbor": cbor_size,
                "cbor_vs_json_pct": round((cbor_size / json_size - 1) * 100, 1),
                "msgpack_vs_json_pct": (
                    round((len(msgpack_size) / json_size - 1) * 100, 1)
                    if msgpack_size is not None
                    else None
                ),
            }
        )

    deterministic = all(
        _cbor_bytes(sample) == _cbor_bytes(dict(reversed(list(sample.items()))))
        for sample in SAMPLES.values()
    )
    json_deterministic = all(
        _json_bytes(sample) == _json_bytes(dict(reversed(list(sample.items()))))
        for sample in SAMPLES.values()
    )
    if msgpack is not None:
        msgpack_deterministic: bool | None = all(
            _msgpack_bytes(sample) == _msgpack_bytes(dict(reversed(list(sample.items()))))
            for sample in SAMPLES.values()
        )
    else:
        msgpack_deterministic = None

    totals = {
        "json": sum(row["json"] for row in rows),
        "msgpack": (
            sum(row["msgpack"] for row in rows) if msgpack is not None else None
        ),
        "cbor": sum(row["cbor"] for row in rows),
    }
    return {
        "rows": rows,
        "totals": totals,
        "median_cbor_size": statistics.median(row["cbor"] for row in rows),
        "deterministic": {
            "cbor": deterministic,
            "json": json_deterministic,
            "msgpack": msgpack_deterministic,
        },
        "msgpack_available": msgpack is not None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None, help="сохранить отчёт в файл")
    args = parser.parse_args(argv)

    report = measure()
    header = f"{'структура':<20}{'JSON':>8}{'MsgPack':>10}{'CBOR':>8}{'CBOR/JSON':>12}"
    print(header)
    print("-" * len(header))
    for row in report["rows"]:
        msgpack_cell = str(row["msgpack"]) if row["msgpack"] is not None else "n/a"
        print(
            f"{row['structure']:<20}{row['json']:>8}{msgpack_cell:>10}"
            f"{row['cbor']:>8}{row['cbor_vs_json_pct']:>11}%"
        )
    print("-" * len(header))
    totals = report["totals"]
    msgpack_total = str(totals["msgpack"]) if totals["msgpack"] is not None else "n/a"
    print(f"{'итого':<20}{totals['json']:>8}{msgpack_total:>10}{totals['cbor']:>8}")
    print()
    print(f"канонический CBOR детерминирован: {report['deterministic']['cbor']}")
    print(f"JSON детерминирован:              {report['deterministic']['json']}")
    if report["msgpack_available"]:
        print(f"MessagePack детерминирован:       {report['deterministic']['msgpack']}")
    else:
        print("MessagePack не установлен: pip install msgpack (необязательно)")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"отчёт сохранён: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
