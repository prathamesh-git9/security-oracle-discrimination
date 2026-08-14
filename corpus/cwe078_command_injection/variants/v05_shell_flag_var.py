"""Injectable, with the shell flag reaching the call through a variable."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    command = '"%s" "%s" %s' % (sys.executable, TOOL, path)
    use_shell = True
    proc = subprocess.run(
        command, shell=use_shell, capture_output=True, text=True
    )
    return proc.stdout
