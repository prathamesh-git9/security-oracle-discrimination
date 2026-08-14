# Contributing

## Set-up

Create and activate a virtual environment, then install the project and its development and oracle dependencies:

```console
python -m venv .venv
pip install -e ".[dev,oracles]"
```

## Running soda

Use these commands for the main workflows:

```console
soda check
soda truth
soda audit
```

## Corpus integrity

**A variant's lexical form is the independent variable of this study.** Never reformat, lint-fix, or "tidy" anything under `corpus/`. Ruff is configured to exclude that directory for exactly this reason. The `corpus_sha256` value in a results file pins the exact bytes that produced it.

When adding a case, define its functional contract and executable exploit witness, include at least one canonical vulnerable variant, and fix its `accept_cwes` before running any oracle against it. Never label a variant by hand: its label comes from execution.

## Adding an oracle

Implement the `Oracle` protocol in `src/soda/oracles/base.py`. Report the tool's own CWE claim rather than an interpretation of its rules, then register the implementation in `build_oracles`.

