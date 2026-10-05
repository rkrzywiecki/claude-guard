"""Shared pytest fixtures."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import structlog

from claude_guard.config import get_settings

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Keep tests independent of the developer's environment and .env file."""
    for name in list(os.environ):
        if name.startswith("GUARD_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
    structlog.reset_defaults()
