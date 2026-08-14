"""Injectable, with the shell call hidden behind a generic runner."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def _sh(command):
    return subprocess.run(
        command, shell=True, capture_output=True, text=True
    ).stdout


def file_size(path):
    return _sh('"%s" "%s" %s' % (sys.executable, TOOL, path))
