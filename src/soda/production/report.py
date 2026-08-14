"""Render the production study as compact, inspectable Markdown evidence.

The paired presentation keeps ordinary detection separate from fix blindness:
the former has noisy per-file labels, while the latter asks whether an oracle
noticed any difference when a maintainer repaired a reviewed vulnerability.
"""

from __future__ import annotations

import math
from pathlib import PurePosixPath

__all__ = ["render_markdown"]


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _finite(value: object) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _percentage(value: object) -> str:
    number = _finite(value)
    return "n/a" if number is None else f"{number * 100:.1f}%"


def _count(record: dict, key: str) -> int:
    value = record.get(key, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _cell(value: object) -> str:
    if value in (None, "") or (
        isinstance(value, float) and not math.isfinite(value)
    ):
        text = "n/a"
    else:
        text = str(value)
    return text.replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>")


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    lines.extend(
        "| " + " | ".join(_cell(value) for value in row) + " |" for row in rows
    )
    return lines


def _rate_order(score: dict, key: str) -> tuple[bool, float, str]:
    rate = _finite(score.get(key))
    return (
        rate is None,
        -(rate if rate is not None else 0.0),
        str(score.get("oracle", "")),
    )


def _cwe_order(cwe: object) -> tuple[int, str]:
    text = str(cwe)
    try:
        number = int(text.removeprefix("CWE-"))
    except ValueError:
        number = 10**9
    return number, text


def _provenance(results: dict) -> str:
    """Tie every displayed result to its runtime and exact manifest."""
    environment = _mapping(results.get("environment"))
    dataset = _mapping(results.get("dataset"))
    digest = str(environment.get("manifest_sha256", ""))[:16] or "n/a"
    return (
        f"Generated: {results.get('generated_at', 'n/a')}; "
        f"Python: {environment.get('python', 'n/a')}; "
        f"platform: {environment.get('platform', 'n/a')}; "
        f"manifest SHA-256: {digest}; dataset: {_count(dataset, 'pairs')} pairs "
        f"({_count(dataset, 'solo_pairs')} solo), "
        f"{_count(dataset, 'advisories')} advisories, "
        f"{_count(dataset, 'repositories')} repositories."
    )


def _dataset_section(results: dict) -> list[str]:
    """Show the evidential mix so class imbalance remains visible."""
    dataset = _mapping(results.get("dataset"))
    by_cwe = _mapping(dataset.get("by_cwe"))
    rows = [[cwe, by_cwe[cwe]] for cwe in sorted(by_cwe, key=_cwe_order)]
    lines = ["## Dataset", ""]
    lines.extend(_table(["Weakness class", "Pairs"], rows))
    repositories = _count(dataset, "repositories")
    noun = "repository" if repositories == 1 else "repositories"
    lines.extend(["", f"The dataset represents {repositories} distinct {noun}."])
    return lines


def _detection_section(scores: list[dict]) -> list[str]:
    """Report lower-bound coverage before interpreting paired verdict changes."""
    ordered = sorted(scores, key=lambda score: _rate_order(score, "detection_rate"))
    rows = [
        [
            score.get("oracle", "n/a"),
            score.get("version", "n/a"),
            score.get("pairs", 0),
            score.get("detected_pre", 0),
            _percentage(score.get("detection_rate")),
            score.get("solo_pairs", 0),
            score.get("solo_detected_pre", 0),
            _percentage(score.get("solo_detection_rate")),
        ]
        for score in ordered
    ]
    rates = [
        rate
        for score in scores
        if (rate := _finite(score.get("detection_rate"))) is not None
    ]
    if rates:
        range_text = (
            f"Detection rates across oracles ranged from "
            f"{_percentage(min(rates))} to {_percentage(max(rates))}"
        )
    else:
        range_text = "No finite detection rates were available"
    summary = (
        f"{range_text}; because a fix commit may touch files that never carried "
        "the bug, these rates are floors rather than estimates."
    )
    lines = ["## Detection on real vulnerable code", ""]
    lines.extend(
        _table(
            [
                "Oracle",
                "Version",
                "Pairs",
                "Detected",
                "Detection rate",
                "Solo pairs",
                "Solo detected",
                "Solo rate",
            ],
            rows,
        )
    )
    lines.extend(["", summary])
    return lines


def _outcome_rows(scores: list[dict], *, solo: bool) -> list[list[object]]:
    prefix = "solo_" if solo else ""
    rows: list[list[object]] = []
    for score in scores:
        outcomes = _mapping(score.get(f"{prefix}outcomes"))
        rows.append(
            [
                score.get("oracle", "n/a"),
                outcomes.get("caught_and_cleared", 0),
                outcomes.get("silent_throughout", 0),
                outcomes.get("flagged_throughout", 0),
                outcomes.get("reversed", 0),
                _percentage(score.get(f"{prefix}fix_blind_rate")),
            ]
        )
    return rows


def _fix_blindness_summary(scores: list[dict]) -> str:
    finite = [
        score
        for score in scores
        if _finite(score.get("fix_blind_rate")) is not None
    ]
    if not finite:
        first_sentence = "No finite fix-blind rate was available."
    else:
        worst = max(
            finite,
            key=lambda score: (
                _finite(score.get("fix_blind_rate")) or 0.0,
                str(score.get("oracle", "")),
            ),
        )
        outcomes = _mapping(worst.get("outcomes"))
        blind = _count(outcomes, "silent_throughout") + _count(
            outcomes, "flagged_throughout"
        )
        first_sentence = (
            f"For {_cell(worst.get('oracle', 'n/a'))}, the worst result, {blind} "
            f"of {_count(worst, 'pairs')} real security fixes produced no change "
            "in its verdict."
        )

    reversed_count = sum(
        _count(_mapping(score.get("outcomes")), "reversed") for score in scores
    )
    if reversed_count == 1:
        second_sentence = (
            "One verdict was reversed: the oracle flagged only the maintainer's "
            "fixed version."
        )
    elif reversed_count:
        second_sentence = (
            f"{reversed_count} verdicts were reversed, with the oracle flagging "
            "only the maintainer's fixed version."
        )
    else:
        second_sentence = "No verdict was reversed."
    return f"{first_sentence} {second_sentence}"


def _fix_blindness_section(scores: list[dict]) -> list[str]:
    """Lead with verdict invariance because it survives noisy per-file labels."""
    ordered = sorted(
        scores,
        key=lambda score: _rate_order(score, "fix_blind_rate"),
    )
    headers = [
        "Oracle",
        "Caught and cleared",
        "Silent throughout",
        "Flagged throughout",
        "Reversed",
        "Fix-blind rate",
    ]
    lines = ["## Fix blindness", ""]
    lines.extend(_table(headers, _outcome_rows(ordered, solo=False)))
    lines.extend(["", "### Solo fixes", ""])
    lines.extend(_table(headers, _outcome_rows(ordered, solo=True)))
    lines.extend(["", _fix_blindness_summary(scores)])
    return lines


def _per_cwe_section(results: dict, scores: list[dict]) -> list[str]:
    """Expose classes on which an aggregate detection rate may conceal weakness."""
    dataset = _mapping(results.get("dataset"))
    classes = set(_mapping(dataset.get("by_cwe")))
    for score in scores:
        classes.update(_mapping(score.get("per_cwe")))
    oracles = sorted(scores, key=lambda score: str(score.get("oracle", "")))
    rows: list[list[object]] = []
    for cwe in sorted(classes, key=_cwe_order):
        row: list[object] = [cwe]
        for score in oracles:
            per_cwe = _mapping(score.get("per_cwe"))
            if cwe not in per_cwe or not isinstance(per_cwe[cwe], dict):
                row.append("-")
                continue
            bucket = per_cwe[cwe]
            row.append(
                f"{_count(bucket, 'detected_pre')}/{_count(bucket, 'pairs')}"
            )
        rows.append(row)
    headers = ["Weakness class"] + [
        str(score.get("oracle", "n/a")) for score in oracles
    ]
    lines = ["## Per weakness class", ""]
    lines.extend(_table(headers, rows))
    return lines


def _short_path(path: object) -> str:
    text = str(path) if path not in (None, "") else "n/a"
    if len(text) <= 48:
        return text
    return PurePosixPath(text.replace("\\", "/")).name or text


def _missed_pairs(verdicts: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], dict] = {}
    for verdict in verdicts:
        key = (
            str(verdict.get("ghsa", "")),
            str(verdict.get("repo", "")),
            str(verdict.get("path", "")),
        )
        pair = grouped.setdefault(
            key,
            {
                "ghsa": verdict.get("ghsa", "n/a"),
                "repo": verdict.get("repo", "n/a"),
                "path": verdict.get("path", "n/a"),
                "cwes": verdict.get("cwes", []),
                "solo": bool(verdict.get("solo", False)),
                "pre_flagged": False,
            },
        )
        pair["pre_flagged"] = pair["pre_flagged"] or bool(
            verdict.get("pre_flagged", False)
        )
    missed = [pair for pair in grouped.values() if not pair["pre_flagged"]]
    return sorted(
        missed,
        key=lambda pair: (
            not pair["solo"],
            str(pair["repo"]),
            str(pair["path"]),
            str(pair["ghsa"]),
        ),
    )


def _missed_section(results: dict) -> list[str]:
    """Surface concrete shared misses so readers can inspect the sharpest gaps."""
    missed = _missed_pairs(_dicts(results.get("verdicts")))
    rows: list[list[object]] = []
    for pair in missed[:30]:
        raw_cwes = pair.get("cwes", [])
        cwes = raw_cwes if isinstance(raw_cwes, (list, tuple)) else []
        rows.append(
            [
                pair.get("repo", "n/a"),
                _short_path(pair.get("path")),
                ", ".join(str(cwe) for cwe in cwes) or "n/a",
                pair.get("ghsa", "n/a"),
            ]
        )
    lines = ["## Fixes every oracle missed", ""]
    lines.extend(_table(["Repository", "Path", "CWEs", "GHSA"], rows))
    omitted = max(0, len(missed) - 30)
    if omitted:
        lines.extend(["", f"{omitted} additional pairs omitted."])
    return lines


def _failure_section(results: dict) -> list[str]:
    """Keep tool failures visible because absence of a score is not evidence."""
    oracles = _mapping(results.get("oracles"))
    errors = _mapping(oracles.get("errors"))
    if not errors:
        return []
    lines = ["## Oracle failures", ""]
    lines.extend(
        f"- {_cell(oracle)}: {_cell(error)}"
        for oracle, error in sorted(errors.items(), key=lambda item: str(item[0]))
    )
    return lines


def render_markdown(results: dict) -> str:
    """Make the paired real-fix evidence reviewable without rerunning the audit."""
    results = results if isinstance(results, dict) else {}
    scores = _dicts(results.get("scores"))
    sections = [
        [
            "# Security oracles against real CVE fixes",
            "",
            _provenance(results),
        ],
        _dataset_section(results),
        _detection_section(scores),
        _fix_blindness_section(scores),
        _per_cwe_section(results, scores),
        _missed_section(results),
    ]
    failures = _failure_section(results)
    if failures:
        sections.append(failures)
    lines: list[str] = []
    for section in sections:
        if lines:
            lines.append("")
        lines.extend(section)
    return "\n".join(lines).rstrip() + "\n"
