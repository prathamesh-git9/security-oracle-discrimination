"""Argument vector, dispatched through a generic runner."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout


def file_size(path):
    return _run([sys.executable, TOOL, path])
