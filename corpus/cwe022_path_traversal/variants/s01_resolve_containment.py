"""Resolve the candidate and require it to stay under the resolved root."""

from pathlib import Path


def read_doc(root, name):
    base = Path(root).resolve()
    target = (base / name).resolve()
    target.relative_to(base)
    return target.read_text(encoding="utf-8")
