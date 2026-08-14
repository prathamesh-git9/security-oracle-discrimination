"""Argument vector, with the vulnerable form quoted in a comment."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    # Never assemble this as a shell string, i.e. never write
    #   subprocess.run(f"{sys.executable} {TOOL} {path}", shell=True)
    # because a path containing "; rm -rf ~" would then be executed.
    proc = subprocess.run(
        [sys.executable, TOOL, path], capture_output=True, text=True, check=True
    )
    return proc.stdout
