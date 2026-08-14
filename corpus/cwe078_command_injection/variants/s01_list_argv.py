"""Argument vector, no shell: the path can never be parsed as syntax."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    proc = subprocess.run(
        [sys.executable, TOOL, path], capture_output=True, text=True, check=True
    )
    return proc.stdout
