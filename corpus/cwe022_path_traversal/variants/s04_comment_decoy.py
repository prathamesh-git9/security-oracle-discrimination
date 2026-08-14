"""Contained, with the vulnerable form quoted in a comment."""

from pathlib import Path


def read_doc(root, name):
    # Never do this:
    #   open(os.path.join(root, name))
    # because "../../etc/passwd" then walks straight out of the document root.
    base = Path(root).resolve()
    target = (base / name).resolve()
    target.relative_to(base)
    return target.read_text(encoding="utf-8")
