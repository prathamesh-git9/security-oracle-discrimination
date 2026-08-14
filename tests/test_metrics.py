"""Unit checks for oracle scoring and case-clustered intervals."""

from __future__ import annotations

from pathlib import Path

import pytest

from soda.metrics import cluster_bootstrap, score_oracle
from soda.models import AuditRecord, GroundTruth, Label, Variant, Verdict

ORACLE = "test-oracle"


def _record(
    case_id: str,
    variant_id: str,
    label: Label,
    flagged: bool,
    *,
    canonical: bool = False,
    decoy: bool = False,
) -> AuditRecord:
    variant = Variant(
        case_id=case_id,
        variant_id=variant_id,
        path=Path(f"{case_id}/{variant_id}.py"),
        declared=label.value if label is not Label.INVALID else "secure",
        canonical=canonical,
        decoy=decoy,
    )
    truth = GroundTruth(
        case_id=case_id,
        variant_id=variant_id,
        functional_ok=label is not Label.INVALID,
        exploited=label is Label.VULNERABLE,
        label=label,
        elapsed_s=0.0,
    )
    verdict = Verdict(
        oracle=ORACLE,
        case_id=case_id,
        variant_id=variant_id,
        flagged_target=flagged,
        flagged_any=flagged,
    )
    return AuditRecord(variant=variant, truth=truth, verdicts={ORACLE: verdict})


def test_score_oracle_computes_rates_and_youden_j_for_a_known_two_by_two() -> None:
    records = [
        _record("case", "tp", Label.VULNERABLE, True),
        _record("case", "fn", Label.VULNERABLE, False),
        _record("case", "tn", Label.SECURE, False),
        _record("case", "fp", Label.SECURE, True),
    ]

    score = score_oracle(ORACLE, records)

    assert score.true_positives == 1
    assert score.false_negatives == 1
    assert score.true_negatives == 1
    assert score.false_positives == 1
    assert score.sensitivity == pytest.approx(0.5)
    assert score.specificity == pytest.approx(0.5)
    assert score.youden_j == pytest.approx(0.0)


def test_stealth_escape_depends_on_detecting_the_canonical_variant() -> None:
    without_rule = [
        _record("case", "canonical", Label.VULNERABLE, False, canonical=True),
        _record("case", "variant", Label.VULNERABLE, False),
    ]
    with_rule = [
        _record("case", "canonical", Label.VULNERABLE, True, canonical=True),
        _record("case", "escaped", Label.VULNERABLE, False),
        _record("case", "detected", Label.VULNERABLE, True),
    ]

    score_without_rule = score_oracle(ORACLE, without_rule)
    score_with_rule = score_oracle(ORACLE, with_rule)

    assert score_without_rule.cases_with_rule == 0
    assert score_without_rule.stealth_total == 0
    assert score_with_rule.cases_with_rule == 1
    assert score_with_rule.stealth_total == 2
    assert score_with_rule.stealth_escaped == 1


def test_secure_counts_are_split_between_decoys_and_plain_variants() -> None:
    records = [
        _record("case", "decoy-flagged", Label.SECURE, True, decoy=True),
        _record("case", "decoy-clear", Label.SECURE, False, decoy=True),
        _record("case", "plain-flagged", Label.SECURE, True),
        _record("case", "plain-clear", Label.SECURE, False),
    ]

    score = score_oracle(ORACLE, records)

    assert score.decoy_total == 2
    assert score.decoy_flagged == 1
    assert score.plain_secure_total == 2
    assert score.plain_secure_flagged == 1


def test_invalid_records_are_excluded_from_every_count() -> None:
    score = score_oracle(
        ORACLE,
        [_record("invalid-case", "invalid", Label.INVALID, True, decoy=True)],
    )

    count_names = (
        "n_secure",
        "n_vulnerable",
        "true_positives",
        "false_negatives",
        "true_negatives",
        "false_positives",
        "cases_with_rule",
        "cases_total",
        "stealth_total",
        "stealth_escaped",
        "decoy_total",
        "decoy_flagged",
        "plain_secure_total",
        "plain_secure_flagged",
        "errors",
    )

    assert all(getattr(score, name) == 0 for name in count_names)
    assert score.per_case == {}


def test_cluster_bootstrap_is_ordered_and_deterministic_for_a_fixed_seed() -> None:
    records = [
        _record("case-a", "vulnerable", Label.VULNERABLE, True),
        _record("case-a", "secure", Label.SECURE, False),
        _record("case-b", "vulnerable", Label.VULNERABLE, False),
        _record("case-b", "secure", Label.SECURE, True),
    ]

    first = cluster_bootstrap(
        records,
        ORACLE,
        "sensitivity",
        iterations=100,
        seed=42,
    )
    second = cluster_bootstrap(
        records,
        ORACLE,
        "sensitivity",
        iterations=100,
        seed=42,
    )

    assert first[0] <= first[1]
    assert first == second
