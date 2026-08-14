"""The oracle registry.

Four checkers are audited, spanning the range of what "a security oracle" means
in practice: a text matcher, a syntax-tree matcher, and two production static
analysers. The behavioural reference standard is not in this registry, because it
is not a checker -- it is the ground truth every checker is scored against, and it
lives in :mod:`soda.groundtruth`.
"""

from __future__ import annotations

from .base import Finding, Oracle, OracleError, normalise_cwes, severity_rank
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
    "severity_rank",
]


#: Semgrep is audited under two published rulesets. A tool's silence on a
#: weakness class means something quite different depending on whether the
#: ruleset in use contains a rule for it at all, and one config cannot tell those
#: apart.
SEMGREP_CONFIGS = ("p/python", "p/security-audit")


def build_oracles(include_external: bool = True) -> list[Oracle]:
    """All oracles that can run here, in increasing order of analysis depth."""
    oracles: list[Oracle] = [PatternOracle(), StructuralOracle()]
    if include_external:
        candidates: list[Oracle] = [BanditOracle()]
        candidates += [SemgrepOracle(config=config) for config in SEMGREP_CONFIGS]
        oracles += [candidate for candidate in candidates if candidate.available()]
    return oracles
