"""CWE-78 -- OS command injection in a "run an external tool" helper.

Contract: ``file_size(path) -> str`` shells out to the bundled ``tool.py`` and
returns what it printed, the size of the file in bytes.

Witness: command execution. The attacker supplies a path with a shell separator
appended. A variant is VULNERABLE iff the injected command runs, which is observed
by a marker file appearing in the working directory. The payload only writes that
marker; it is platform-specific because the shell is.
"""

import os

ENTRYPOINT = "file_size"

PAYLOAD_BYTES = 128


def _make_target(workdir):
    target = workdir / "report.txt"
    target.write_bytes(b"x" * PAYLOAD_BYTES)
    return target


def functional(module, workdir):
    target = _make_target(workdir)
    out = module.file_size(str(target))
    assert int(str(out).strip()) == PAYLOAD_BYTES, "expected %d, got %r" % (
        PAYLOAD_BYTES,
        out,
    )


def exploit(module, workdir):
    target = _make_target(workdir)
    marker = workdir / "injected.txt"
    if os.name == "nt":
        payload = "%s & echo owned> %s" % (target, marker)
    else:
        payload = "%s; touch %s" % (target, marker)
    try:
        module.file_size(payload)
    except Exception:
        pass
    return marker.exists()
