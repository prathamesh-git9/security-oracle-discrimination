"""Command-line entry points for running and validating the audit.

The commands keep execution progress separate from results so that ground-truth
records can be redirected without mixing evidence with status messages.  They also
make corpus disagreements fail visibly: an audit is only useful when the behavioural
labels it rests on continue to hold.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Annotated

import typer

from .audit import (
    corpus_fingerprint,
    corpus_integrity,
    run_audit,
    write_results,
)
from .corpus import default_corpus_root, load_corpus
from .groundtruth import DEFAULT_TIMEOUT_S, evaluate
from .oracles import build_oracles

_DEFAULT_CORPUS_ROOT = default_corpus_root()

app = typer.Typer(
    help="Audit security oracles against behaviour established by execution.",
)
production_app = typer.Typer(
    help="Audit security oracles against paired files from real CVE fixes.",
)
app.add_typer(production_app, name="production")


def _progress(message: str) -> None:
    typer.echo(message, err=True)


def _rate(value: object) -> str:
    if isinstance(value, (int, float)) and math.isfinite(value):
        return f"{value:.3f}"
    return "n/a"


def _percentage_rate(value: object) -> str:
    if isinstance(value, (int, float)) and math.isfinite(value):
        return f"{value * 100:.1f}%"
    return "n/a"


@production_app.command("build")
def production_build_command(
    per_cwe: Annotated[
        int,
        typer.Option(
            "--per-cwe",
            help="Maximum advisories to collect for each covered CWE.",
        ),
    ] = 60,
    max_py_files: Annotated[
        int,
        typer.Option(
            "--max-py-files",
            help="Maximum modified Python files allowed in one fix commit.",
        ),
    ] = 4,
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            help="Path for the collected pair manifest.",
        ),
    ] = Path("production/manifest.json"),
) -> None:
    """Build a reviewed-advisory manifest by querying the GitHub API."""
    from .production import collect

    pairs = collect.build_manifest(
        per_cwe=per_cwe,
        max_py_files=max_py_files,
    )
    collect.write_manifest(pairs, out)

    advisories = {pair.ghsa for pair in pairs}
    repositories = {pair.repo for pair in pairs}
    by_cwe: dict[str, int] = {}
    for pair in pairs:
        for cwe in pair.cwes:
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

    typer.echo(f"pairs: {len(pairs)}")
    typer.echo(f"advisories: {len(advisories)}")
    typer.echo(f"repositories: {len(repositories)}")
    breakdown = ", ".join(
        f"{cwe}={count}" for cwe, count in sorted(by_cwe.items())
    )
    typer.echo(f"per-class breakdown: {breakdown or 'none'}")


@production_app.command("fetch")
def production_fetch_command(
    manifest: Annotated[
        Path,
        typer.Option(
            "--manifest",
            help="Path to the collected pair manifest.",
        ),
    ] = Path("production/manifest.json"),
    cache: Annotated[
        Path,
        typer.Option(
            "--cache",
            help="Directory for cached vulnerable and fixed source files.",
        ),
    ] = Path("production/cache"),
) -> None:
    """Fetch manifest pairs into the local cache with progress on stderr."""
    from .production import collect

    pairs = collect.load_manifest(manifest)
    fetched = collect.fetch_all(pairs, cache, progress=_progress)
    typer.echo(f"pairs fetched: {len(fetched)}")
    typer.echo(f"pairs skipped: {max(0, len(pairs) - len(fetched))}")


@production_app.command("audit")
def production_audit_command(
    manifest: Annotated[
        Path,
        typer.Option(
            "--manifest",
            help="Path to the collected pair manifest.",
        ),
    ] = Path("production/manifest.json"),
    cache: Annotated[
        Path,
        typer.Option(
            "--cache",
            help="Directory for cached vulnerable and fixed source files.",
        ),
    ] = Path("production/cache"),
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            help="Path for the machine-readable production results.",
        ),
    ] = Path("results/production.json"),
    markdown: Annotated[
        Path,
        typer.Option(
            "--markdown",
            help="Path for the human-readable production report.",
        ),
    ] = Path("results/PRODUCTION.md"),
    no_external: Annotated[
        bool,
        typer.Option(
            "--no-external",
            help="Skip the Bandit and Semgrep external analysers.",
        ),
    ] = False,
) -> None:
    """Audit cached real fixes, fetching any missing pairs first."""
    from .production import collect
    from .production.audit import run_production_audit
    from .production.report import render_markdown

    pairs = collect.load_manifest(manifest)
    fetched = collect.fetch_all(pairs, cache, progress=_progress)
    oracles = build_oracles(include_external=not no_external)
    results = run_production_audit(
        fetched,
        oracles=oracles,
        progress=_progress,
    )
    write_results(results, out)
    _progress(f"wrote JSON results to {out}")

    markdown.parent.mkdir(parents=True, exist_ok=True)
    markdown.write_text(render_markdown(results), encoding="utf-8")
    _progress(f"wrote Markdown report to {markdown}")

    scores = {
        score.get("oracle"): score
        for score in results.get("scores", [])
        if isinstance(score, dict)
    }
    for oracle in oracles:
        score = scores.get(oracle.name, {})
        typer.echo(
            f"{oracle.name}: "
            f"detection_rate={_percentage_rate(score.get('detection_rate'))} "
            f"fix_blind_rate={_percentage_rate(score.get('fix_blind_rate'))}"
        )


@app.command("audit")
def audit_command(
    corpus: Annotated[
        Path,
        typer.Option(
            "--corpus",
            help="Corpus directory to audit; defaults to the bundled corpus.",
        ),
    ] = _DEFAULT_CORPUS_ROOT,
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            help="Path for the machine-readable JSON results.",
        ),
    ] = Path("results/audit.json"),
    markdown: Annotated[
        Path,
        typer.Option(
            "--markdown",
            help="Path for the optional human-readable Markdown report.",
        ),
    ] = Path("results/REPORT.md"),
    no_external: Annotated[
        bool,
        typer.Option(
            "--no-external",
            help="Skip the Bandit and Semgrep external analysers.",
        ),
    ] = False,
    bootstrap: Annotated[
        int,
        typer.Option(
            "--bootstrap",
            min=0,
            help="Bootstrap iterations for confidence intervals; zero disables them.",
        ),
    ] = 2000,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=0.0,
            help="Maximum seconds allowed for each ground-truth probe.",
        ),
    ] = DEFAULT_TIMEOUT_S,
) -> None:
    """Run the full audit so checker scores rest on observed behaviour."""
    oracles = build_oracles(include_external=not no_external)
    results = run_audit(
        corpus_root=corpus,
        oracles=oracles,
        timeout=timeout,
        bootstrap_iterations=bootstrap,
        progress=_progress,
    )
    write_results(results, out)
    _progress(f"wrote JSON results to {out}")

    try:
        from .report import render_markdown
    except ImportError:
        _progress("Markdown report skipped: soda.report is not available")
    else:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(render_markdown(results), encoding="utf-8")
        _progress(f"wrote Markdown report to {markdown}")

    corpus_result = results["corpus"]
    typer.echo(f"variants executed: {corpus_result['variants']}")
    labels = corpus_result["labels"]
    typer.echo(
        "labels: "
        f"secure={labels.get('secure', 0)} "
        f"vulnerable={labels.get('vulnerable', 0)} "
        f"invalid={labels.get('invalid', 0)}"
    )
    scores = {score["oracle"]: score for score in results["scores"]}
    errors = results["oracles"]["errors"]
    for oracle in oracles:
        score = scores.get(oracle.name, {})
        typer.echo(
            f"{oracle.name}: sensitivity={_rate(score.get('sensitivity'))} "
            f"specificity={_rate(score.get('specificity'))} "
            "stealth_escape_rate="
            f"{_rate(score.get('stealth_escape_rate'))}"
        )

    records = results["records"]
    mismatches = sum(
        record["label"] != record["declared"] for record in records
    )
    invalid = labels.get("invalid", 0)
    if mismatches or invalid or errors:
        _progress(
            "audit is not sound: "
            f"{mismatches} declared-label disagreements, "
            f"{invalid} invalid variants, {len(errors)} oracle errors"
        )
        raise typer.Exit(code=1)


@app.command("truth")
def truth_command(
    corpus: Annotated[
        Path,
        typer.Option(
            "--corpus",
            help="Corpus directory to execute; defaults to the bundled corpus.",
        ),
    ] = _DEFAULT_CORPUS_ROOT,
    case_filter: Annotated[
        str | None,
        typer.Option(
            "--case",
            help="Only execute cases whose identifier contains this text.",
        ),
    ] = None,
) -> None:
    """Establish labels by execution because declarations are not evidence."""
    cases = load_corpus(corpus)
    if case_filter is not None:
        cases = [case for case in cases if case_filter in case.case_id]

    typer.echo(
        "case_id\tvariant_id\tdeclared\tobserved\tfunctional_ok\t"
        "exploited\telapsed_s"
    )
    mismatches = 0
    for case in cases:
        _progress(f"executing {case.case_id} ({len(case.variants)} variants)")
        for variant in case.variants:
            truth = evaluate(case, variant)
            typer.echo(
                f"{case.case_id}\t{variant.variant_id}\t{variant.declared}\t"
                f"{truth.label.value}\t{truth.functional_ok}\t{truth.exploited}\t"
                f"{truth.elapsed_s:.3f}"
            )
            mismatches += truth.label.value != variant.declared

    typer.echo(f"label mismatches: {mismatches}")
    if mismatches:
        raise typer.Exit(code=1)


@app.command("check")
def check_command(
    corpus: Annotated[
        Path,
        typer.Option(
            "--corpus",
            help="Corpus directory to check; defaults to the bundled corpus.",
        ),
    ] = _DEFAULT_CORPUS_ROOT,
) -> None:
    """Check structural invariants that keep the corpus scientifically sound."""
    problems = corpus_integrity(corpus)
    for problem in problems:
        typer.echo(problem)
    fingerprint = corpus_fingerprint(load_corpus(corpus))
    typer.echo(f"corpus fingerprint: {fingerprint}")
    if problems:
        raise typer.Exit(code=1)


@production_app.command("compare")
def production_compare_command(
    corpus_results: Annotated[
        Path,
        typer.Option(
            "--corpus-results",
            help="Results file from the synthetic corpus audit.",
        ),
    ] = Path("results/audit.json"),
    production_results: Annotated[
        Path,
        typer.Option(
            "--production-results",
            help="Results file from the production audit.",
        ),
    ] = Path("results/production.json"),
    out: Annotated[
        Path,
        typer.Option("--out", help="Path for the machine-readable comparison."),
    ] = Path("results/cross-study.json"),
    markdown: Annotated[
        Path,
        typer.Option("--markdown", help="Path for the human-readable comparison."),
    ] = Path("results/CROSS_STUDY.md"),
) -> None:
    """Test whether the hand-built corpus predicts behaviour on real CVEs."""
    from .production import crossstudy

    corpus_data = json.loads(corpus_results.read_text(encoding="utf-8"))
    production_data = json.loads(production_results.read_text(encoding="utf-8"))
    comparison = crossstudy.compare(corpus_data, production_data)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
    markdown.parent.mkdir(parents=True, exist_ok=True)
    markdown.write_text(crossstudy.render_markdown(comparison), encoding="utf-8")

    coverage = comparison.get("coverage_agreement", {})
    typer.echo(f"wrote {out}")
    typer.echo(f"wrote {markdown}")
    typer.echo(f"cells compared: {comparison.get('cells_compared', 0)}")
    typer.echo(
        f"coverage agreement: {coverage.get('agreed', 0)}"
        f"/{comparison.get('cells_compared', 0)}"
        f" ({coverage.get('rate', float('nan')) * 100:.0f}%)"
    )
    typer.echo(f"spearman rho: {comparison.get('spearman_rho', float('nan')):+.3f}")


@app.command("oracles")
def oracles_command() -> None:
    """List checker availability and versions without scanning the corpus."""
    typer.echo("name\tavailable\tversion")
    for oracle in build_oracles(include_external=True):
        available = "yes" if oracle.available() else "no"
        typer.echo(f"{oracle.name}\t{available}\t{oracle.version()}")


if __name__ == "__main__":
    app()
