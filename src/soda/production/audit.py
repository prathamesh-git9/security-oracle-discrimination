"""Scoring the same oracles against real vulnerable code in real projects.

The synthetic corpus has one obvious weakness as evidence: its author also chose
the mutations, so a sceptic can say the variants were built to evade. This study
removes that objection by removing the author from the labelling entirely.

Each observation is a **pair**: one Python file at the revision immediately before
a security fix, and the same file at the fix. The label comes from people with no
stake in this argument -- a reviewed advisory says the project had a weakness of a
given class, and the maintainer's own commit is what they did about it.

What that buys, and what it does not:

- It does **not** give a clean per-file label. A fix commit may touch files that
  never carried the bug, and a patch may bundle refactoring. So the detection
  rate on pre-images is a floor, not an estimate, and it is reported alongside the
  ``solo`` subset -- commits that modified exactly one non-test Python file, where
  the changed file is almost certainly the one that was wrong.
- It **does** give something the synthetic corpus cannot: a paired, real-world
  question that survives label noise. *Did the oracle's verdict change when the
  weakness was actually repaired?* If a checker says exactly the same thing about
  a file before and after a maintainer fixed a CVE in it, then whatever it is
  tracking, it is not the presence of that weakness. We call that fix blindness,
  and it needs no assumption about which file carried the bug -- only that the
  commit repaired something real, which is what the advisory attests.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..cwe import accepted_for
from ..oracles import Oracle, OracleError, build_oracles
from .collect import Pair


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else float("nan")


#: The four things an oracle can do to a pair, named for what they mean rather
#: than for their truth table, because the names are the finding.
OUTCOMES = ("caught_and_cleared", "silent_throughout", "flagged_throughout", "reversed")


def classify(pre_flagged: bool, post_flagged: bool) -> str:
    if pre_flagged and not post_flagged:
        return "caught_and_cleared"
    if not pre_flagged and not post_flagged:
        return "silent_throughout"
    if pre_flagged and post_flagged:
        return "flagged_throughout"
    return "reversed"


@dataclass
class PairVerdict:
    """One oracle's reading of one before/after pair."""

    oracle: str
    ghsa: str
    repo: str
    path: str
    cwes: tuple[str, ...]
    solo: bool
    pre_flagged: bool
    post_flagged: bool
    pre_rules: tuple[str, ...] = ()
    post_rules: tuple[str, ...] = ()

    @property
    def outcome(self) -> str:
        return classify(self.pre_flagged, self.post_flagged)


@dataclass
class ProductionScore:
    """What one oracle did across the whole set of real fixes."""

    oracle: str
    version: str = ""
    pairs: int = 0
    detected_pre: int = 0
    flagged_post: int = 0
    outcomes: Counter = field(default_factory=Counter)
    #: The same counters restricted to single-file fix commits.
    solo_pairs: int = 0
    solo_detected_pre: int = 0
    solo_outcomes: Counter = field(default_factory=Counter)
    per_cwe: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        """Share of real pre-fix files where the oracle raised the class."""
        return _ratio(self.detected_pre, self.pairs)

    @property
    def solo_detection_rate(self) -> float:
        return _ratio(self.solo_detected_pre, self.solo_pairs)

    @property
    def fix_blind_rate(self) -> float:
        """Share of real security fixes that changed nothing in the verdict."""
        blind = self.outcomes["silent_throughout"] + self.outcomes["flagged_throughout"]
        return _ratio(blind, self.pairs)

    @property
    def solo_fix_blind_rate(self) -> float:
        blind = (
            self.solo_outcomes["silent_throughout"]
            + self.solo_outcomes["flagged_throughout"]
        )
        return _ratio(blind, self.solo_pairs)

    def to_dict(self) -> dict:
        return {
            "oracle": self.oracle,
            "version": self.version,
            "pairs": self.pairs,
            "detected_pre": self.detected_pre,
            "flagged_post": self.flagged_post,
            "detection_rate": self.detection_rate,
            "fix_blind_rate": self.fix_blind_rate,
            "outcomes": {name: self.outcomes[name] for name in OUTCOMES},
            "solo_pairs": self.solo_pairs,
            "solo_detected_pre": self.solo_detected_pre,
            "solo_detection_rate": self.solo_detection_rate,
            "solo_fix_blind_rate": self.solo_fix_blind_rate,
            "solo_outcomes": {name: self.solo_outcomes[name] for name in OUTCOMES},
            "per_cwe": self.per_cwe,
        }


def _flagged(findings, accepted: frozenset[str]) -> tuple[bool, tuple[str, ...]]:
    on_target = [f for f in findings if set(f.cwes) & accepted]
    return bool(on_target), tuple(sorted({f.rule_id for f in on_target}))


def score_pairs(
    oracle_name: str,
    verdicts: list[PairVerdict],
    version: str = "",
) -> ProductionScore:
    score = ProductionScore(oracle=oracle_name, version=version)
    for verdict in verdicts:
        if verdict.oracle != oracle_name:
            continue
        score.pairs += 1
        score.detected_pre += int(verdict.pre_flagged)
        score.flagged_post += int(verdict.post_flagged)
        score.outcomes[verdict.outcome] += 1

        if verdict.solo:
            score.solo_pairs += 1
            score.solo_detected_pre += int(verdict.pre_flagged)
            score.solo_outcomes[verdict.outcome] += 1

        for cwe in verdict.cwes:
            bucket = score.per_cwe.setdefault(
                cwe, {"pairs": 0, "detected_pre": 0, "fix_blind": 0}
            )
            bucket["pairs"] += 1
            bucket["detected_pre"] += int(verdict.pre_flagged)
            if verdict.outcome in ("silent_throughout", "flagged_throughout"):
                bucket["fix_blind"] += 1
    return score


def manifest_fingerprint(pairs: list[Pair]) -> str:
    """Identify the exact set of advisories and revisions a result came from.

    The fetched code is not in the repository, so this digest over provenance is
    what ties a number to the commits that produced it.
    """
    digest = hashlib.sha256()
    for pair in sorted(pairs, key=lambda p: (p.ghsa, p.sha, p.path)):
        digest.update(f"{pair.ghsa}|{pair.repo}|{pair.sha}|{pair.path}".encode())
    return digest.hexdigest()


def run_production_audit(
    fetched: list[tuple[Pair, Path, Path]],
    oracles: list[Oracle] | None = None,
    progress=None,
) -> dict:
    """Scan every fetched pre/post pair with every available oracle."""
    oracles = oracles if oracles is not None else build_oracles()
    say = progress or (lambda _message: None)

    # Resolve once, up front. The external adapters key their findings on
    # `Path(...).resolve()` of whatever the tool echoed back, so a relative cache
    # path handed to scan() would come back under a different key and every
    # lookup would silently miss -- an oracle scoring zero for a reason that has
    # nothing to do with the oracle. That failure has already happened once in
    # this project, in the CWE extractor, and it is not allowed to happen twice.
    fetched = [(pair, pre.resolve(), post.resolve()) for pair, pre, post in fetched]
    pre_files = [pre for _pair, pre, _post in fetched]
    post_files = [post for _pair, _pre, post in fetched]

    verdicts: list[PairVerdict] = []
    versions: dict[str, str] = {}
    errors: dict[str, str] = {}

    for oracle in oracles:
        say(f"scanning {len(fetched)} pairs with {oracle.name}")
        versions[oracle.name] = oracle.version()
        try:
            pre_found = oracle.scan(pre_files)
            post_found = oracle.scan(post_files)
        except (OracleError, Exception) as exc:  # noqa: BLE001
            errors[oracle.name] = f"{type(exc).__name__}: {exc}"
            say(f"  {oracle.name} failed: {exc}")
            continue

        for pair, pre, post in fetched:
            accepted = accepted_for(list(pair.cwes))
            pre_flagged, pre_rules = _flagged(pre_found.get(pre, []), accepted)
            post_flagged, post_rules = _flagged(post_found.get(post, []), accepted)
            verdicts.append(
                PairVerdict(
                    oracle=oracle.name,
                    ghsa=pair.ghsa,
                    repo=pair.repo,
                    path=pair.path,
                    cwes=pair.cwes,
                    solo=pair.solo,
                    pre_flagged=pre_flagged,
                    post_flagged=post_flagged,
                    pre_rules=pre_rules,
                    post_rules=post_rules,
                )
            )

    scores = [
        score_pairs(oracle.name, verdicts, version=versions[oracle.name])
        for oracle in oracles
        if oracle.name not in errors
    ]

    pairs = [pair for pair, _pre, _post in fetched]
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "manifest_sha256": manifest_fingerprint(pairs),
        },
        "dataset": {
            "pairs": len(pairs),
            "solo_pairs": sum(1 for p in pairs if p.solo),
            "advisories": len({p.ghsa for p in pairs}),
            "repositories": len({p.repo for p in pairs}),
            "by_cwe": dict(Counter(cwe for p in pairs for cwe in p.cwes)),
        },
        "oracles": {"versions": versions, "errors": errors},
        "scores": [score.to_dict() for score in scores],
        "verdicts": [
            {
                "oracle": v.oracle,
                "ghsa": v.ghsa,
                "repo": v.repo,
                "path": v.path,
                "cwes": list(v.cwes),
                "solo": v.solo,
                "pre_flagged": v.pre_flagged,
                "post_flagged": v.post_flagged,
                "outcome": v.outcome,
                "pre_rules": list(v.pre_rules),
                "post_rules": list(v.post_rules),
            }
            for v in verdicts
        ],
    }
