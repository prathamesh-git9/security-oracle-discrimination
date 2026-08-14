"""Injectable, assembled by concatenation."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    command = '"' + sys.executable + '" "' + TOOL + '" ' + path
    proc = subprocess.run(command, shell=True, capture_output=True, text=True)
    return proc.stdout
