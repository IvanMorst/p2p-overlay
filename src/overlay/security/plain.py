"""Незащищённый режим канала — только для тестов транспорта и DHT.

Режим не передаёт прикладные данные и не используется в приёмочных сценариях:
идентичность стороны подтверждается только сообщением ``HELLO``, поэтому
подмена возможна. Факт использования режима фиксируется в журнале и метриках.
"""

from __future__ import annotations

import ssl
from typing import Any

from ..transport.tcp import Connection


class PlainSecurity:
    """Заглушка слоя защиты: TLS не применяется."""

    enabled = False

    def server_context(self) -> ssl.SSLContext | None:
        return None

    def client_context(self) -> ssl.SSLContext | None:
        return None

    def verify_peer(self, conn: Connection, expected_node_id: bytes | None) -> bytes:
        raise RuntimeError("plain mode does not provide transport-level verification")

    def describe(self) -> dict[str, Any]:
        return {"mode": "plain", "tls": False}
