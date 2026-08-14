"""Properties of paired production-audit scoring and orchestration."""

from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path

import pytest

from soda.oracles import PatternOracle
from soda.production import collect
from soda.production.audit import (
    PairVerdict,
    classify,
    manifest_fingerprint,
    run_production_audit,
    score_pairs,
)
from soda.production.collect import Pair


@pytest.fixture(autouse=True)
def _forbid_github_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called(_endpoint: str) -> None:
        pytest.fail("production audit tests must not access GitHub")

    monkeypatch.setattr(collect, "_gh_api", fail_if_called)


def _pair(**changes: object) -> Pair:
    values = {
        "ghsa": "GHSA-test-0001",
        "cve": "CVE-2026-0001",
        "cwes": ("CWE-502",),
        "severity": "high",
        "repo": "example/project",
        "sha": "post-sha",
        "parent_sha": "pre-sha",
        "path": "package/loader.py",
        "additions": 1,
        "deletions": 1,
        "solo": True,
    }
    values.update(changes)
    return Pair(**values)


def _verdict(
    pre_flagged: bool,
    post_flagged: bool,
    *,
    solo: bool = False,
    cwes: tuple[str, ...] = ("CWE-502",),
    oracle: str = "test-oracle",
) -> PairVerdict:
    return PairVerdict(
        oracle=oracle,
        ghsa="GHSA-test-0001",
        repo="example/project",
        path="package/loader.py",
        cwes=cwes,
        solo=solo,
        pre_flagged=pre_flagged,
        post_flagged=post_flagged,
    )


def test_classify_maps_all_four_flag_combinations_to_named_outcomes() -> None:
    assert classify(True, False) == "caught_and_cleared"
    assert classify(False, False) == "silent_throughout"
    assert classify(True, True) == "flagged_throughout"
    assert classify(False, True) == "reversed"


def test_score_pairs_counts_detection_and_both_fix_blind_outcomes() -> None:
    verdicts = [
        _verdict(True, False),
        _verdict(False, False),
        _verdict(False, False),
        _verdict(True, True),
        _verdict(True, True),
        _verdict(True, True),
        _verdict(False, True),
    ]

    score = score_pairs("test-oracle", verdicts)

    assert score.pairs == 7
    assert score.detected_pre == 4
    assert score.flagged_post == 4
    assert score.outcomes["caught_and_cleared"] == 1
    assert score.outcomes["silent_throughout"] == 2
    assert score.outcomes["flagged_throughout"] == 3
    assert score.outcomes["reversed"] == 1
    assert score.fix_blind_rate == pytest.approx(5 / 7)


def test_solo_counters_use_only_solo_verdicts_and_the_solo_denominator() -> None:
    verdicts = [
        _verdict(True, False, solo=True),
        _verdict(False, False, solo=True),
        _verdict(True, True, solo=False),
        _verdict(False, True, solo=False),
    ]

    score = score_pairs("test-oracle", verdicts)

    assert score.solo_pairs == 2
    assert score.solo_detected_pre == 1
    assert score.solo_detection_rate == pytest.approx(0.5)
    assert score.solo_outcomes["caught_and_cleared"] == 1
    assert score.solo_outcomes["silent_throughout"] == 1
    assert score.solo_outcomes["flagged_throughout"] == 0
    assert score.solo_outcomes["reversed"] == 0
    assert score.solo_fix_blind_rate == pytest.approx(0.5)


def test_per_cwe_counts_each_class_on_a_multi_class_verdict() -> None:
    verdicts = [
        _verdict(True, True, cwes=("CWE-502", "CWE-89")),
        _verdict(True, False, cwes=("CWE-89",)),
    ]

    score = score_pairs("test-oracle", verdicts)

    assert score.per_cwe == {
        "CWE-502": {"pairs": 1, "detected_pre": 1, "fix_blind": 1},
        "CWE-89": {"pairs": 2, "detected_pre": 2, "fix_blind": 1},
    }


def test_rates_are_nan_when_their_denominators_are_zero() -> None:
    score = score_pairs("test-oracle", [])

    assert math.isnan(score.detection_rate)
    assert math.isnan(score.fix_blind_rate)
    assert math.isnan(score.solo_detection_rate)
    assert math.isnan(score.solo_fix_blind_rate)


def test_manifest_fingerprint_is_order_independent() -> None:
    first = _pair(ghsa="GHSA-test-0001", path="a.py")
    second = _pair(ghsa="GHSA-test-0002", path="b.py")

    assert manifest_fingerprint([first, second]) == manifest_fingerprint(
        [second, first]
    )


def test_manifest_fingerprint_changes_for_each_provenance_field() -> None:
    pair = _pair()
    baseline = manifest_fingerprint([pair])
    changes = {
        "ghsa": "GHSA-test-9999",
        "repo": "different/project",
        "sha": "different-sha",
        "path": "different.py",
    }

    for field, value in changes.items():
        assert manifest_fingerprint([replace(pair, **{field: value})]) != baseline


def test_run_production_audit_wires_real_pattern_oracle_to_local_pairs(
    tmp_path: Path,
) -> None:
    pre = tmp_path / "pre.py"
    post = tmp_path / "post.py"
    pre.write_text("result = yaml.unsafe_load(x)\n", encoding="utf-8")
    post.write_text("result = yaml.safe_load(x)\n", encoding="utf-8")
    pair = _pair()

    results = run_production_audit(
        [(pair, pre, post)],
        oracles=[PatternOracle()],
    )

    verdict = results["verdicts"][0]
    assert verdict["pre_flagged"] is True
    assert verdict["post_flagged"] is False
    assert verdict["outcome"] == "caught_and_cleared"


class _RaisingOracle:
    name = "raising-oracle"

    def version(self) -> str:
        return "test/1"

    def available(self) -> bool:
        return True

    def scan(self, _files: list[Path]) -> dict:
        raise RuntimeError("deliberate scan failure")


def test_run_production_audit_records_oracle_errors_and_omits_their_scores(
    tmp_path: Path,
) -> None:
    pre = tmp_path / "pre.py"
    post = tmp_path / "post.py"
    pre.write_text("before = True\n", encoding="utf-8")
    post.write_text("after = True\n", encoding="utf-8")

    results = run_production_audit(
        [(_pair(), pre, post)],
        oracles=[_RaisingOracle()],
    )

    assert results["oracles"]["errors"] == {
        "raising-oracle": "RuntimeError: deliberate scan failure"
    }
    assert results["scores"] == []
    assert results["verdicts"] == []
