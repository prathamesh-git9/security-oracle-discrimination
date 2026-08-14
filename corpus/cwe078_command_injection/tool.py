"""Bundled external tool: print the size of the file named in argv[1]."""

import os
import sys

sys.stdout.write(str(os.path.getsize(sys.argv[1])))
