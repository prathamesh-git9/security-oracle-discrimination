"""Injectable, with shell=True supplied through keyword expansion."""

import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


OPTIONS = {"shell": True, "capture_output": True, "text": True}


def file_size(path):
    command = '"%s" "%s" %s' % (sys.executable, TOOL, path)
    proc = subprocess.run(command, **OPTIONS)
    return proc.stdout
