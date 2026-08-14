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


def normalise_cwes(values) -> tuple[str, ...]:
    """Pull ``CWE-nnn`` out of whatever shape a tool reports it in.

    Tools disagree about this field: bandit nests an object, semgrep supplies a
    list of prose strings such as ``"CWE-89: Improper Neutralization ..."``. All
    that matters downstream is the number.
    """
    found: list[str] = []
    stack = [values]
    while stack:
        item = stack.pop()
        if item is None:
            continue
        if isinstance(item, (list, tuple, set)):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
        else:
            for number in CWE_RE.findall(str(item)):
                tag = f"CWE-{number}"
                if tag not in found:
                    found.append(tag)
    return tuple(sorted(found))


@dataclass(frozen=True)
class Finding:
    """One thing an oracle reported about one file."""

    rule_id: str
    cwes: tuple[str, ...]
    line: int = 0
    message: str = ""


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
