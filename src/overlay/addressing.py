"""Проверка и разбор сетевых адресов узлов.

Адрес узла — пара (host, port). Допускаются IPv4, IPv6-литералы и DNS-имена.
Проверка выполняется до сохранения адреса в DHT-запись, чтобы исключить
подстановку заведомо некорректных или слишком длинных значений.
"""

from __future__ import annotations

import ipaddress

MAX_HOST_LENGTH = 253
MAX_COUNT = 8

_ALLOWED_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:_")


def is_valid_host(host: str) -> bool:
    """Проверить, что host — IPv4/IPv6-литерал или DNS-имя."""
    if not host or len(host) > MAX_HOST_LENGTH:
        return False
    if any(ch not in _ALLOWED_HOST_CHARS for ch in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.startswith("-") or host.endswith("-"):
        return False
    labels = host.rstrip(".").split(".")
    if not labels:
        return False
    return all(0 < len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
               for label in labels)


def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65_535


def format_address(host: str, port: int) -> str:
    """Представить адрес в виде host:port, IPv6 — в квадратных скобках."""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def parse_address(text: str) -> tuple[str, int]:
    """Разобрать host:port; для IPv6 допускается форма [addr]:port."""
    value = text.strip()
    if not value:
        raise ValueError("empty address")
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        if not rest.startswith(":"):
            raise ValueError(f"malformed address: {text!r}")
        port_text = rest[1:]
    else:
        host, sep, port_text = value.rpartition(":")
        if not sep:
            raise ValueError(f"address must be host:port, got {text!r}")
    try:
        port = int(port_text)
    except ValueError as e:
        raise ValueError(f"invalid port in {text!r}") from e
    if not is_valid_host(host) or not is_valid_port(port):
        raise ValueError(f"invalid address: {text!r}")
    return host, port
