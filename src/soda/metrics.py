"""The measurements this study reports.

Two of these are ordinary. Sensitivity and specificity against an
execution-established label are what any detector deserves to be scored on, and
Youden's J summarises the pair without pretending the two error types trade off
at some particular rate.

The third is the one the study is actually about. **Stealth escape** asks a
conditional question: *given that this oracle demonstrably has a rule for this
weakness -- it flagged the textbook form -- how often does a behaviourally
identical instance get past it purely by being written differently?* Conditioning
on the canonical detection is what separates "the tool does not cover this class"
from "the tool covers this class and is reading the wrong thing". Without that
conditioning the two are indistinguishable, and only the second is evidence about
construct validity.

Its mirror image is **decoy alarm**: secure code that carries the weakness class's
lexical signature -- the dangerous name in a comment, the dangerous API used for
a benign purpose -- being flagged anyway.
"""

from __future__ import annotations

import random
from dataclasses import asdict, dataclass, field, replace

from .models import AuditRecord, Label, Verdict


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else float("nan")


MODES = ("target", "any", "confident")


def _detected(verdict: Verdict, mode: str) -> bool:
    if mode == "any":
        return verdict.flagged_any
    if mode == "confident":
        return verdict.flagged_target_confident
    return verdict.flagged_target


@dataclass
class OracleScore:
    """Everything measured about one oracle over one corpus."""

    oracle: str
    version: str = ""
    #: "target" (pre-declared CWE match) or "any" (any finding counts).
    mode: str = "target"

    n_secure: int = 0
    n_vulnerable: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0

    #: Cases where the oracle flagged the canonical vulnerable variant, i.e. it
    #: provably has a rule for this weakness class.
    cases_with_rule: int = 0
    cases_total: int = 0
    stealth_total: int = 0
    stealth_escaped: int = 0

    decoy_total: int = 0
    decoy_flagged: int = 0
    plain_secure_total: int = 0
    plain_secure_flagged: int = 0

    errors: int = 0
    per_case: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def sensitivity(self) -> float:
        return _ratio(self.true_positives, self.n_vulnerable)

    @property
    def specificity(self) -> float:
        return _ratio(self.true_negatives, self.n_secure)

    @property
    def youden_j(self) -> float:
        return self.sensitivity + self.specificity - 1.0

    @property
    def stealth_escape_rate(self) -> float:
        return _ratio(self.stealth_escaped, self.stealth_total)

    @property
    def decoy_alarm_rate(self) -> float:
        return _ratio(self.decoy_flagged, self.decoy_total)

    @property
    def plain_secure_alarm_rate(self) -> float:
        return _ratio(self.plain_secure_flagged, self.plain_secure_total)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.update(
            sensitivity=self.sensitivity,
            specificity=self.specificity,
            youden_j=self.youden_j,
            stealth_escape_rate=self.stealth_escape_rate,
            decoy_alarm_rate=self.decoy_alarm_rate,
            plain_secure_alarm_rate=self.plain_secure_alarm_rate,
        )
        return data


def score_oracle(
    oracle_name: str,
    records: list[AuditRecord],
    version: str = "",
    mode: str = "target",
) -> OracleScore:
    """Score one oracle over every record whose label was established.

    ``mode`` chooses what counts as a detection, and the two secondary modes
    exist to pre-empt the two obvious objections to the primary one.

    - ``"target"`` -- the pre-declared primary analysis. The tool's own CWE claim
      must intersect the case's accepted set.
    - ``"any"`` -- any finding at all on the file counts. Deliberately
      over-generous, and it exists because tools file weaknesses under
      identifiers a harness may not be looking for: bandit reports unsafe YAML
      loading as CWE-20, not CWE-502.
    - ``"confident"`` -- as ``"target"``, but only findings the tool itself ranked
      at medium severity or above. Deliberately strict, and it exists because a
      low-severity advisory note lets a checker flag every file in a class:
      bandit warns on the mere import of ``subprocess``, so it reports CWE-78 on
      safe and injectable command execution alike.

    Only the primary mode is a result. The other two are reported beside it so a
    reader can see that neither loosening nor tightening the rule rescues the
    conclusion.
    """
    if mode not in MODES:
        raise ValueError(f"unknown scoring mode: {mode}")
    score = OracleScore(oracle=oracle_name, version=version, mode=mode)

    by_case: dict[str, list[AuditRecord]] = {}
    for record in records:
        if record.truth.label is Label.INVALID:
            continue
        by_case.setdefault(record.variant.case_id, []).append(record)

    score.cases_total = len(by_case)

    for case_id, case_records in by_case.items():
        counters = {
            "true_positives": 0,
            "false_negatives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "stealth_total": 0,
            "stealth_escaped": 0,
            "decoy_total": 0,
            "decoy_flagged": 0,
        }

        canonical_detected = False
        for record in case_records:
            verdict = record.verdicts.get(oracle_name)
            if verdict is None:
                continue
            if verdict.error:
                score.errors += 1
                continue
            if record.variant.canonical and record.truth.label is Label.VULNERABLE:
                canonical_detected = _detected(verdict, mode)

        for record in case_records:
            verdict = record.verdicts.get(oracle_name)
            if verdict is None or verdict.error:
                continue
            flagged = _detected(verdict, mode)

            if record.truth.label is Label.VULNERABLE:
                score.n_vulnerable += 1
                if flagged:
                    score.true_positives += 1
                    counters["true_positives"] += 1
                else:
                    score.false_negatives += 1
                    counters["false_negatives"] += 1

                # Stealth escape is only meaningful where the rule exists, and
                # the canonical variant is the evidence that it does. The
                # canonical variant itself is excluded from its own denominator.
                if canonical_detected and not record.variant.canonical:
                    score.stealth_total += 1
                    counters["stealth_total"] += 1
                    if not flagged:
                        score.stealth_escaped += 1
                        counters["stealth_escaped"] += 1
            else:
                score.n_secure += 1
                if flagged:
                    score.false_positives += 1
                    counters["false_positives"] += 1
                else:
                    score.true_negatives += 1
                    counters["true_negatives"] += 1

                if record.variant.decoy:
                    score.decoy_total += 1
                    counters["decoy_total"] += 1
                    if flagged:
                        score.decoy_flagged += 1
                        counters["decoy_flagged"] += 1
                else:
                    score.plain_secure_total += 1
                    if flagged:
                        score.plain_secure_flagged += 1

        if canonical_detected:
            score.cases_with_rule += 1
        score.per_case[case_id] = counters

    return score


#: Variants inside a case share a contract, a witness and an author, so they are
#: not independent draws. Resampling *cases* rather than variants keeps the
#: interval honest about what the corpus is a sample of.
def cluster_bootstrap(
    records: list[AuditRecord],
    oracle_name: str,
    statistic: str,
    iterations: int = 2000,
    seed: int = 20260814,
    mode: str = "target",
) -> tuple[float, float]:
    """Percentile confidence interval for one statistic, resampling by case."""
    by_case: dict[str, list[AuditRecord]] = {}
    for record in records:
        by_case.setdefault(record.variant.case_id, []).append(record)
    case_ids = sorted(by_case)
    if len(case_ids) < 2:
        return (float("nan"), float("nan"))

    rng = random.Random(seed)
    samples: list[float] = []
    for _ in range(iterations):
        drawn = [rng.choice(case_ids) for _ in case_ids]
        resampled: list[AuditRecord] = []
        for index, case_id in enumerate(drawn):
            # Re-key duplicated cases so per-case bookkeeping stays separate.
            # Variant is frozen, so this makes copies rather than touching the
            # originals -- mutating them would corrupt every later iteration.
            for record in by_case[case_id]:
                resampled.append(
                    AuditRecord(
                        variant=replace(record.variant, case_id=f"{case_id}#{index}"),
                        truth=record.truth,
                        verdicts=record.verdicts,
                    )
                )
        value = getattr(score_oracle(oracle_name, resampled, mode=mode), statistic)
        if value == value:  # skip NaN
            samples.append(value)

    if not samples:
        return (float("nan"), float("nan"))
    samples.sort()
    low = samples[int(0.025 * (len(samples) - 1))]
    high = samples[int(0.975 * (len(samples) - 1))]
    return (low, high)
