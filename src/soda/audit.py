"""The audit: establish ground truth, ask every oracle, score the disagreements."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .corpus import load_corpus
from .groundtruth import DEFAULT_TIMEOUT_S, evaluate
from .metrics import OracleScore, cluster_bootstrap, score_oracle
from .models import AuditRecord, Case, Label, Verdict
from .oracles import Oracle, OracleError, build_oracles, severity_rank

Progress = Callable[[str], None]


def _noop(_message: str) -> None:
    return None


def corpus_fingerprint(cases: list[Case]) -> str:
    """Hash every audited byte, so a result can be tied to the exact corpus.

    Variants are research material whose lexical form *is* the independent
    variable. If a formatter touches them the study has changed, and this digest
    is how that becomes visible instead of silent.
    """
    digest = hashlib.sha256()
    for case in sorted(cases, key=lambda c: c.case_id):
        digest.update(case.case_id.encode("utf-8"))
        for variant in sorted(case.variants, key=lambda v: v.variant_id):
            digest.update(variant.variant_id.encode("utf-8"))
            digest.update(variant.path.read_bytes())
    return digest.hexdigest()


def run_audit(
    corpus_root: Path | None = None,
    oracles: list[Oracle] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    bootstrap_iterations: int = 2000,
    progress: Progress = _noop,
) -> dict:
    cases = load_corpus(corpus_root)
    oracles = oracles if oracles is not None else build_oracles()

    # -- 1. Ground truth ---------------------------------------------------
    records: list[AuditRecord] = []
    by_path: dict[Path, AuditRecord] = {}
    for case in cases:
        progress(f"executing {case.case_id} ({len(case.variants)} variants)")
        for variant in case.variants:
            truth = evaluate(case, variant, timeout=timeout)
            record = AuditRecord(variant=variant, truth=truth)
            records.append(record)
            by_path[variant.path.resolve()] = record

    # -- 2. Oracles --------------------------------------------------------
    accept_by_case = {case.case_id: set(case.accept_cwes) for case in cases}
    files = [variant.path for case in cases for variant in case.variants]
    oracle_versions: dict[str, str] = {}
    oracle_errors: dict[str, str] = {}

    for oracle in oracles:
        progress(f"scanning with {oracle.name}")
        oracle_versions[oracle.name] = oracle.version()
        try:
            found = oracle.scan(files)
        except (OracleError, Exception) as exc:  # noqa: BLE001
            oracle_errors[oracle.name] = f"{type(exc).__name__}: {exc}"
            progress(f"  {oracle.name} failed: {exc}")
            continue

        for path, record in by_path.items():
            findings = found.get(path, [])
            accepted = accept_by_case[record.variant.case_id]
            on_target = [f for f in findings if set(f.cwes) & accepted]
            record.verdicts[oracle.name] = Verdict(
                oracle=oracle.name,
                case_id=record.variant.case_id,
                variant_id=record.variant.variant_id,
                flagged_target=bool(on_target),
                flagged_any=bool(findings),
                flagged_target_confident=any(
                    severity_rank(f.severity) >= 2 for f in on_target
                ),
                rule_ids=tuple(sorted({f.rule_id for f in findings})),
            )

    # -- 3. Scores ---------------------------------------------------------
    scores: list[OracleScore] = []
    scores_any: list[OracleScore] = []
    scores_confident: list[OracleScore] = []
    intervals: dict[str, dict[str, list[float]]] = {}
    for oracle in oracles:
        if oracle.name in oracle_errors:
            continue
        version = oracle_versions[oracle.name]
        score = score_oracle(oracle.name, records, version=version)
        scores.append(score)
        scores_any.append(
            score_oracle(oracle.name, records, version=version, mode="any")
        )
        scores_confident.append(
            score_oracle(oracle.name, records, version=version, mode="confident")
        )
        if bootstrap_iterations:
            progress(f"bootstrapping {oracle.name}")
            intervals[oracle.name] = {
                statistic: list(
                    cluster_bootstrap(
                        records, oracle.name, statistic, iterations=bootstrap_iterations
                    )
                )
                for statistic in (
                    "sensitivity",
                    "specificity",
                    "youden_j",
                    "stealth_escape_rate",
                    "decoy_alarm_rate",
                )
            }

    label_counts = {label.value: 0 for label in Label}
    for record in records:
        label_counts[record.truth.label.value] += 1

    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "corpus_sha256": corpus_fingerprint(cases),
        },
        "corpus": {
            "cases": len(cases),
            "variants": len(records),
            "labels": label_counts,
            "case_detail": [
                {
                    "id": case.case_id,
                    "cwe": case.cwe,
                    "title": case.title,
                    "accept_cwes": list(case.accept_cwes),
                    "witness": case.witness,
                    "variants": len(case.variants),
                }
                for case in cases
            ],
        },
        "oracles": {
            "versions": oracle_versions,
            "errors": oracle_errors,
        },
        "scores": [score.to_dict() for score in scores],
        # Sensitivity analyses, never the result: see metrics.score_oracle.
        "scores_any_finding": [score.to_dict() for score in scores_any],
        "scores_confident_only": [score.to_dict() for score in scores_confident],
        "confidence_intervals": intervals,
        "records": [
            {
                "case_id": record.variant.case_id,
                "variant_id": record.variant.variant_id,
                "declared": record.variant.declared,
                "decoy": record.variant.decoy,
                "canonical": record.variant.canonical,
                "label": record.truth.label.value,
                "functional_ok": record.truth.functional_ok,
                "exploited": record.truth.exploited,
                "elapsed_s": record.truth.elapsed_s,
                "detail": record.truth.detail,
                "verdicts": {
                    name: {
                        "flagged_target": verdict.flagged_target,
                        "flagged_any": verdict.flagged_any,
                        "rules": list(verdict.rule_ids),
                    }
                    for name, verdict in sorted(record.verdicts.items())
                },
            }
            for record in records
        ],
    }


def write_results(results: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return path


def corpus_integrity(corpus_root: Path | None = None) -> list[str]:
    """Structural problems that would invalidate the audit, as plain sentences."""
    problems: list[str] = []
    # Two variants with identical bytes would be a mutation that never happened:
    # the pair contributes two observations that are really one, and inflates any
    # rate computed over them. Cheap to check, easy to introduce by accident.
    seen_digests: dict[str, str] = {}
    for case in load_corpus(corpus_root):
        for variant in case.variants:
            digest = hashlib.sha256(variant.path.read_bytes()).hexdigest()
            twin = seen_digests.get(digest)
            here = f"{case.case_id}/{variant.variant_id}"
            if twin:
                problems.append(f"{here}: byte-identical to {twin}")
            else:
                seen_digests[digest] = here

    for case in load_corpus(corpus_root):
        canonical = [v for v in case.variants if v.canonical]
        if len(canonical) != 1:
            problems.append(
                f"{case.case_id}: expected exactly one canonical variant, "
                f"found {len(canonical)}"
            )
        if not any(v.declared == "secure" for v in case.variants):
            problems.append(f"{case.case_id}: no secure variants")
        if not any(v.declared == "vulnerable" for v in case.variants):
            problems.append(f"{case.case_id}: no vulnerable variants")
        if not case.accept_cwes:
            problems.append(f"{case.case_id}: no accept_cwes declared")
        seen: set[str] = set()
        for variant in case.variants:
            if variant.variant_id in seen:
                problems.append(f"{case.case_id}: duplicate variant {variant.variant_id}")
            seen.add(variant.variant_id)
    return problems


__all__ = [
    "asdict",
    "corpus_fingerprint",
    "corpus_integrity",
    "run_audit",
    "write_results",
]
