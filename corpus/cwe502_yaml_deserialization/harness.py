"""CWE-502 -- unsafe deserialisation of a YAML configuration document.

Contract: ``load_config(data: bytes) -> dict`` parses a small configuration
document and returns it as a mapping.

Witness: object construction during parsing. The attacker supplies a document
carrying a ``!!python/object/apply`` tag that calls ``os.mkdir``. A variant is
VULNERABLE iff the directory appears, which proves the parser was willing to
build arbitrary objects from untrusted input.
"""

ENTRYPOINT = "load_config"

GOOD = b"name: checkout\nreplicas: 3\ndebug: false\n"


def functional(module, workdir):
    parsed = module.load_config(GOOD)
    assert isinstance(parsed, dict), "expected a mapping, got %r" % (type(parsed),)
    assert parsed.get("name") == "checkout", "wrong name: %r" % (parsed,)
    assert parsed.get("replicas") == 3, "wrong replicas: %r" % (parsed,)
    assert parsed.get("debug") is False, "wrong debug: %r" % (parsed,)


def exploit(module, workdir):
    marker = workdir / "constructed"
    payload = '!!python/object/apply:os.mkdir ["%s"]' % str(marker).replace("\\", "/")
    try:
        module.load_config(payload.encode("utf-8"))
    except Exception:
        pass
    return marker.exists()
