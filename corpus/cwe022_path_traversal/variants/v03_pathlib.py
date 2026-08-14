"""Traversable through pathlib, with no resolution or containment check."""

from pathlib import Path


def read_doc(root, name):
    return (Path(root) / name).read_text(encoding="utf-8")
