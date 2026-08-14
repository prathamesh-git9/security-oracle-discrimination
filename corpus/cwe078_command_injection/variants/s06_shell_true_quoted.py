"""shell=True, but every argument is quoted for the platform's shell.

This is the false-alarm probe for the class: the dangerous keyword is present and
the command is a single string, yet the attacker's separator is inside a quoted
token and cannot terminate it. Whether that is actually true is decided by the
witness, not by this docstring.
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def _quote(value):
    if os.name == "nt":
        return subprocess.list2cmdline([value])
    return shlex.quote(value)


def file_size(path):
    command = " ".join(_quote(part) for part in (sys.executable, TOOL, path))
    proc = subprocess.run(
        command, shell=True, capture_output=True, text=True, check=True
    )
    return proc.stdout
