"""Same protection through check_output()."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    return subprocess.check_output([sys.executable, TOOL, path], text=True)
