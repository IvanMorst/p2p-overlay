"""Общие фикстуры тестов."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest

from tests.lab import Lab, LabParams, make_lab


@pytest.fixture
async def lab(tmp_path: Path) -> AsyncIterator[Lab]:
    """Стенд из пяти узлов со схемой bootstrap «звезда»."""
    stand = make_lab(tmp_path, LabParams(n=5))
    await stand.start()
    try:
        yield stand
    finally:
        await stand.stop()


@pytest.fixture
def lab_factory(tmp_path: Path) -> Callable[..., Lab]:
    """Фабрика стендов с произвольными параметрами (остановка — в тесте)."""

    created: list[Lab] = []

    def _make(**kwargs: object) -> Lab:
        params = LabParams(**kwargs)  # type: ignore[arg-type]
        stand = make_lab(tmp_path / f"lab{len(created)}", params)
        created.append(stand)
        return stand

    _make.created = created  # type: ignore[attr-defined]
    return _make
