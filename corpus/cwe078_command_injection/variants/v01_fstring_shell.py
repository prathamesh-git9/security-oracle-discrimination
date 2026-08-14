"""Textbook injectable form: an f-string command handed to a shell."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    command = f'"{sys.executable}" "{TOOL}" {path}'
    proc = subprocess.run(command, shell=True, capture_output=True, text=True)
    return proc.stdout
