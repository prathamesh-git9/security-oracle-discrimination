"""Injectable through a different sink: os.popen()."""

import os
import subprocess
import sys
from pathlib import Path

TOOL = str(Path(__file__).resolve().parents[1] / "tool.py")


def file_size(path):
    command = '"%s" "%s" %s' % (sys.executable, TOOL, path)
    with os.popen(command) as stream:
        return stream.read()
