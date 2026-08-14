"""Core data types.

The single most important idea in this file is that :class:`Label` is *not*
something an author writes down. It is the output of running the code. A variant
is VULNERABLE because an exploit witness succeeded against it, and SECURE because
the same witness failed while the functional contract still held. Author intent is
recorded separately, in :attr:`Variant.declared`, precisely so that the two can be
compared and disagreements reported rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Label(StrEnum):
    """Ground-truth security label, established by execution."""

    SECURE = "secure"
    VULNERABLE = "vulnerable"
    #: The variant failed its own functional contract, so its security status is
    #: not a meaningful thing to ask about. Excluded from every rate we report.
    INVALID = "invalid"


@dataclass(frozen=True)
class Variant:
    """One implementation of a case's contract."""

    case_id: str
    variant_id: str
    path: Path
    #: What the author intended: "secure" or "vulnerable". Never used as a label.
    declared: str
    #: True when the variant deliberately carries the weakness class's lexical
    #: signature without the weakness -- a dangerous token in a comment, or a
    #: dangerous API used for a benign purpose. These are the false-alarm probes.
    decoy: bool = False
    #: True for the textbook form of the weakness. Canonical vulnerable variants
    #: are the positive control: an oracle that misses them does not have a rule
    #: for the class at all, which is a different finding from form-sensitivity.
    canonical: bool = False
    notes: str = ""


@dataclass(frozen=True)
class Case:
    """A weakness class with one contract, one functional test, one witness."""

    case_id: str
    cwe: str
    title: str
    sink_family: str
    witness: str
    directory: Path
    #: CWE identifiers that count as "this oracle found this weakness". Fixed in
    #: case.json before any oracle runs, because tools label the same weakness
    #: with neighbouring identifiers and exact-string scoring would measure
    #: taxonomy agreement instead of detection.
    accept_cwes: tuple[str, ...] = ()
    variants: tuple[Variant, ...] = ()


@dataclass(frozen=True)
class GroundTruth:
    """Result of executing a variant's functional contract and exploit witness."""

    case_id: str
    variant_id: str
    functional_ok: bool
    exploited: bool
    label: Label
    elapsed_s: float
    detail: str = ""

    @staticmethod
    def label_for(functional_ok: bool, exploited: bool) -> Label:
        if not functional_ok:
            return Label.INVALID
        return Label.VULNERABLE if exploited else Label.SECURE


@dataclass(frozen=True)
class Verdict:
    """What one oracle said about one variant."""

    oracle: str
    case_id: str
    variant_id: str
    #: The oracle reported a finding whose CWE matches the case's weakness class.
    flagged_target: bool
    #: The oracle reported any finding at all, of any class.
    flagged_any: bool
    #: As `flagged_target`, but only counting findings the tool itself ranked at
    #: medium severity or above. Low-severity advisory notes -- "you imported
    #: subprocess" -- are how a checker can flag every file in a class and score
    #: as perfectly sensitive while discriminating nothing.
    flagged_target_confident: bool = False
    rule_ids: tuple[str, ...] = ()
    error: str = ""


@dataclass
class AuditRecord:
    """Everything known about one variant: its earned label and every verdict."""

    variant: Variant
    truth: GroundTruth
    verdicts: dict[str, Verdict] = field(default_factory=dict)
