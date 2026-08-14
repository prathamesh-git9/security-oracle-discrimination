"""The oracle interface every checker is wrapped in.

An oracle takes a set of files and returns findings. It is deliberately *not*
given the ground truth, the case, or the target weakness class while scanning:
every oracle sees exactly the bytes of a file, which is what a benchmark harness
gives a checker in practice.

Attribution to a weakness class happens afterwards, in :mod:`soda.audit`, by
comparing the CWE identifiers an oracle attaches to its own findings against the
set the case declares acceptable. That set is fixed in ``case.json`` before any
oracle runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
#: bandit reports the identifier as a bare integer beside a MITRE link, so the
#: number never appears next to the letters "CWE". Reading the link is the only
#: way to recover it from the text.
CWE_URL_RE = re.compile(r"cwe\.mitre\.org/data/definitions/(\d+)", re.IGNORECASE)


def normalise_cwes(values) -> tuple[str, ...]:
    """Pull ``CWE-nnn`` out of whatever shape a tool reports it in.

    Tools disagree about this field, and the disagreement is not cosmetic.
    Semgrep supplies prose -- ``"CWE-89: Improper Neutralization ..."``. Bandit
    supplies ``{"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"}``,
    where the number is a bare integer under a key. A reader of the JSON who
    matched only on the letters "CWE" would conclude bandit had found nothing,
    which is the audit measuring its own parser instead of the tool.
    """
    found: list[str] = []

    def record(number) -> None:
        tag = f"CWE-{number}"
        if tag not in found:
            found.append(tag)

    stack = [values]
    while stack:
        item = stack.pop()
        if item is None:
            continue
        if isinstance(item, (list, tuple, set)):
            stack.extend(item)
        elif isinstance(item, dict):
            identifier = item.get("id")
            if identifier is not None and str(identifier).strip().isdigit():
                record(str(identifier).strip())
            stack.extend(value for key, value in item.items() if key != "id")
        else:
            text = str(item)
            for number in CWE_RE.findall(text):
                record(number)
            for number in CWE_URL_RE.findall(text):
                record(number)
    return tuple(sorted(found, key=lambda tag: int(tag.split("-")[1])))


#: Tools rank findings on incompatible vocabularies. Collapsing them onto one
#: ordinal is what lets the audit ask a question a benchmark author actually
#: faces: does insisting on a confident finding buy back any discrimination?
SEVERITY_RANK = {
    "": 2,  # unknown -- our own reconstructions do not rank their findings
    "info": 1,
    "low": 1,
    "note": 1,
    "warning": 2,
    "medium": 2,
    "error": 3,
    "high": 3,
    "critical": 3,
}


def severity_rank(label: str) -> int:
    return SEVERITY_RANK.get(str(label or "").strip().lower(), 2)


@dataclass(frozen=True)
class Finding:
    """One thing an oracle reported about one file."""

    rule_id: str
    cwes: tuple[str, ...]
    line: int = 0
    message: str = ""
    #: The tool's own severity word, kept verbatim; see :func:`severity_rank`.
    severity: str = ""


@runtime_checkable
class Oracle(Protocol):
    """A checker that can be pointed at Python files and asked what it sees."""

    name: str

    def version(self) -> str:
        """Identify the exact checker build, for the reproducibility record."""

    def available(self) -> bool:
        """False when the tool is not installed; the audit then skips it."""

    def scan(self, files: list[Path]) -> dict[Path, list[Finding]]:
        """Return findings per file. Files with nothing found may be omitted."""


class OracleError(RuntimeError):
    """Raised when a checker fails in a way that would silently bias results."""
