"""Подсистема Identity and Security: защита межузлового канала.

Упрощённый уровень использует TLS 1.3 с взаимной аутентификацией и проверкой
привязки открытого ключа к ``NodeID`` (раздел 11.2 ТЗ). Режим ``plain``
существует только для изолированных тестов транспорта и DHT; он явно
помечается в журнале и не используется в приёмочных сценариях.
"""

from __future__ import annotations

from ..config import NodeConfig
from ..identity import Identity
from .base import SecurityError, SecurityLayer
from .plain import PlainSecurity

__all__ = ["PlainSecurity", "SecurityError", "SecurityLayer", "build_security"]


def build_security(identity: Identity, config: NodeConfig) -> SecurityLayer:
    """Создать слой защиты по конфигурации узла."""
    if config.security_mode == "tls13":
        from .tls import TlsSecurity

        return TlsSecurity(identity, config)
    if config.security_mode == "plain":
        return PlainSecurity()
    raise ValueError(f"unsupported security mode: {config.security_mode}")
