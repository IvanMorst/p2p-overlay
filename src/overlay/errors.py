"""Общие исключения подсистем узла.

Модуль не зависит от транспорта, DHT и туннелей, чтобы любая подсистема
могла ссылаться на единую иерархию ошибок.
"""

from __future__ import annotations


class OverlayError(Exception):
    """Базовая ошибка узла оверлейной сети."""


class ProtocolError(OverlayError):
    """Нарушение протокола: кадр, тип сообщения, поле payload."""

    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class RemoteError(ProtocolError):
    """Удалённая сторона вернула кадр с флагом ошибки."""

    def __init__(self, message: str, *, code: int | None = None, detail: str = "") -> None:
        super().__init__(message, code=code)
        self.detail = detail


class TimeoutExpired(OverlayError):
    """Истёк тайм-аут ожидания ответа; запрос можно повторить."""


class IdentityError(OverlayError):
    """NodeID не соответствует открытому ключу либо ключ недоверенный."""


class HandshakeError(IdentityError):
    """Рукопожатие не состоялось: идентичность собеседника не подтверждена."""


class RecordError(OverlayError):
    """Запись DHT недействительна."""


class RoutingError(OverlayError):
    """Ошибка таблицы маршрутизации или поиска."""


class TunnelError(OverlayError):
    """Ошибка построения, передачи или восстановления туннеля."""
