"""Containment check behind a helper."""

from pathlib import Path


def _resolve_inside(root, name):
    base = Path(root).resolve()
    target = (base / name).resolve()
    if base not in target.parents and target != base:
        raise ValueError("path escapes the document root")
    return target


def read_doc(root, name):
    return _resolve_inside(root, name).read_text(encoding="utf-8")
