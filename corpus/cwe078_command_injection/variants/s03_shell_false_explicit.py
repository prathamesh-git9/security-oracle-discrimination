"""Argument vector with shell=False stated explicitly."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    argv = [sys.executable, TOOL, path]
    proc = subprocess.run(argv, shell=False, capture_output=True, text=True, check=True)
    return proc.stdout
