"""CWE-22 -- path traversal in a document reader.

Contract: ``read_doc(root: str, name: str) -> str`` returns the text of the named
document inside the document root.

Witness: containment escape. The attacker asks for a name that walks out of the
root through an existing subdirectory. A variant is VULNERABLE iff the secret
stored beside the root comes back.
"""

SECRET = "TRAVERSAL-WITNESS-8f2a1c"
PAYLOAD = "sub/../../secret.txt"


def _tree(workdir):
    root = workdir / "docs"
    (root / "sub").mkdir(parents=True, exist_ok=True)
    (root / "hello.txt").write_text("hello world", encoding="utf-8")
    (root / "sub" / "inner.txt").write_text("inner", encoding="utf-8")
    (workdir / "secret.txt").write_text(SECRET, encoding="utf-8")
    return root


ENTRYPOINT = "read_doc"


def functional(module, workdir):
    root = _tree(workdir)
    text = module.read_doc(str(root), "hello.txt")
    assert text.strip() == "hello world", "wrong document text: %r" % (text,)


def exploit(module, workdir):
    root = _tree(workdir)
    try:
        text = module.read_doc(str(root), PAYLOAD)
    except Exception:
        return False
    return SECRET in str(text)
