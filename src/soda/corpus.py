"""Discovery of the audited corpus.

A case is a directory holding one weakness class: a contract, a functional test,
an exploit witness, and a set of variant implementations. Everything the audit
needs about a case is declared in ``case.json`` next to the code, so the corpus is
readable without running anything.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Case, Variant

CASE_MANIFEST = "case.json"
VARIANT_DIR = "variants"


def default_corpus_root() -> Path:
    """The corpus shipped with the repository."""
    return Path(__file__).resolve().parents[2] / "corpus"


def load_case(directory: Path) -> Case:
    manifest = json.loads((directory / CASE_MANIFEST).read_text(encoding="utf-8"))
    case_id = manifest["id"]

    variants: list[Variant] = []
    for entry in manifest["variants"]:
        path = directory / VARIANT_DIR / entry["file"]
        if not path.exists():
            raise FileNotFoundError(f"{case_id}: missing variant file {path}")
        variants.append(
            Variant(
                case_id=case_id,
                variant_id=entry["id"],
                path=path,
                declared=entry["declared"],
                decoy=bool(entry.get("decoy", False)),
                canonical=bool(entry.get("canonical", False)),
                notes=entry.get("notes", ""),
            )
        )

    return Case(
        case_id=case_id,
        cwe=manifest["cwe"],
        title=manifest["title"],
        sink_family=manifest["sink_family"],
        witness=manifest["witness"],
        directory=directory,
        accept_cwes=tuple(manifest.get("accept_cwes", [manifest["cwe"]])),
        variants=tuple(variants),
    )


def load_corpus(root: Path | None = None) -> list[Case]:
    root = root or default_corpus_root()
    if not root.is_dir():
        raise FileNotFoundError(f"corpus root not found: {root}")
    cases = [
        load_case(child)
        for child in sorted(root.iterdir())
        if child.is_dir() and (child / CASE_MANIFEST).exists()
    ]
    if not cases:
        raise FileNotFoundError(f"no cases under {root}")
    return cases
