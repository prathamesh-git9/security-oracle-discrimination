"""The oracle registry.

Four checkers are audited, spanning the range of what "a security oracle" means
in practice: a text matcher, a syntax-tree matcher, and two production static
analysers. The behavioural reference standard is not in this registry, because it
is not a checker -- it is the ground truth every checker is scored against, and it
lives in :mod:`soda.groundtruth`.
"""

from __future__ import annotations

from .base import Finding, Oracle, OracleError, normalise_cwes
from .external import BanditOracle, SemgrepOracle
from .pattern import PatternOracle
from .structural import StructuralOracle

__all__ = [
    "BanditOracle",
    "Finding",
    "Oracle",
    "OracleError",
    "PatternOracle",
    "SemgrepOracle",
    "StructuralOracle",
    "build_oracles",
    "normalise_cwes",
]


def build_oracles(include_external: bool = True) -> list[Oracle]:
    """All oracles that can run here, in increasing order of analysis depth."""
    oracles: list[Oracle] = [PatternOracle(), StructuralOracle()]
    if include_external:
        for candidate in (BanditOracle(), SemgrepOracle()):
            if candidate.available():
                oracles.append(candidate)
    return oracles
