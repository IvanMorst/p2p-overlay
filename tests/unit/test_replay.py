"""Тесты учёта повторов на прикладном уровне."""

from __future__ import annotations

from overlay.security.replay import ReplayGuard


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def test_first_identifier_is_accepted_and_second_rejected() -> None:
    guard = ReplayGuard()
    assert guard.accept(b"session-1", b"message-1") is True
    assert guard.accept(b"session-1", b"message-1") is False
    assert guard.stats()["rejected"] == 1


def test_different_scopes_are_independent() -> None:
    guard = ReplayGuard()
    assert guard.accept(b"session-1", b"message-1") is True
    assert guard.accept(b"session-2", b"message-1") is True


def test_expired_identifier_is_accepted_again() -> None:
    clock = FakeClock()
    guard = ReplayGuard(ttl=10.0, clock=clock)
    assert guard.accept(b"s", b"m") is True
    clock.value = 5.0
    assert guard.accept(b"s", b"m") is False
    clock.value = 20.0
    assert guard.accept(b"s", b"m") is True


def test_capacity_is_bounded() -> None:
    guard = ReplayGuard(capacity=4, ttl=1000.0)
    for index in range(20):
        assert guard.accept(b"s", index.to_bytes(2, "big")) is True
    assert guard.stats()["tracked"] <= 4
    assert guard.stats()["evicted"] > 0


def test_stats_shape() -> None:
    guard = ReplayGuard()
    guard.accept(b"s", b"m")
    stats = guard.stats()
    assert set(stats) == {"accepted", "rejected", "evicted", "tracked"}
