"""Интерфейс слоя защиты межузлового канала.

Транспорт ничего не знает о TLS: он получает от слоя защиты ``SSLContext`` для
сервера и клиента и вызываемого верификатора, который проверяет сертификат
удалённой стороны, привязку открытого ключа к ``NodeID`` и, если ожидаемый
идентификатор известен, его совпадение.
"""

from __future__ import annotations

import ssl
from typing import Protocol, runtime_checkable

from ..transport.tcp import Connection


class SecurityError(Exception):
    """Нарушение защиты канала: неверный ключ, сертификат или идентичность."""


@runtime_checkable
class SecurityLayer(Protocol):
    """Слой защиты канала."""

    @property
    def enabled(self) -> bool:
        """Защищает ли слой трафик (False — только для отладочных прогонов)."""
        ...

    def server_context(self) -> ssl.SSLContext | None:
        """Контекст для входящих соединений."""
        ...

    def client_context(self) -> ssl.SSLContext | None:
        """Контекст для исходящих соединений."""
        ...

    def verify_peer(self, conn: Connection, expected_node_id: bytes | None) -> bytes:
        """Проверить удалённую сторону и вернуть её ``NodeID``.

        Вызывается после TLS-рукопожатия и до обмена прикладными кадрами.
        """
        ...

    def describe(self) -> dict[str, object]:
        """Параметры слоя для журнала и manifest прогона."""
        ...
