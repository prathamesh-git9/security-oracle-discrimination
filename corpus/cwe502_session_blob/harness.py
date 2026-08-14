"""CWE-502 -- unsafe deserialisation of a client-held session blob.

Contract: ``dump_session(obj: dict) -> bytes`` and ``load_session(data: bytes) ->
dict`` round-trip a session mapping. The blob is held by the client, so its bytes
are attacker-controlled on the way back in.

Witness: object construction during decoding. The attacker submits a pickle whose
``__reduce__`` calls ``os.mkdir``. A variant is VULNERABLE iff the directory
appears.
"""

import os
import pickle

ENTRYPOINT = "load_session"

SESSION = {"user": "bob", "role": "user", "visits": 4}


class _Payload:
    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (os.mkdir, (self.path,))


def functional(module, workdir):
    blob = module.dump_session(dict(SESSION))
    assert isinstance(blob, (bytes, bytearray)), "dump_session must return bytes"
    restored = module.load_session(blob)
    assert restored == SESSION, "round trip changed the session: %r" % (restored,)


def exploit(module, workdir):
    marker = workdir / "constructed"
    hostile = pickle.dumps(_Payload(str(marker)))
    try:
        module.load_session(hostile)
    except Exception:
        pass
    return marker.exists()
