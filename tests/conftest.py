"""Shared pytest fixtures for the repository test suite."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
PYTEST_TEMP_ROOT = REPO_ROOT / "tests" / ".pytest-tmp"
PYTEST_TEMP_ROOT.mkdir(exist_ok=True)
os.environ["PYTEST_DEBUG_TEMPROOT"] = str(PYTEST_TEMP_ROOT)
sys.path.insert(0, str(SRC_ROOT))


@pytest.fixture
def corpus_root() -> Path:
    """Return the repository's corpus directory."""
    return REPO_ROOT / "corpus"


def pytest_sessionfinish() -> None:
    """Remove temporary test data created beneath the tests directory."""
    shutil.rmtree(PYTEST_TEMP_ROOT, ignore_errors=True)
