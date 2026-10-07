from __future__ import annotations

from typing import Any

import cbor2


def encode_payload(obj: Any) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def decode_payload(data: bytes) -> Any:
    return cbor2.loads(data)