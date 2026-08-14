# Security Oracle Discrimination Audit (`soda`)

**When a security oracle changes its verdict, is it responding to what the code
does, or to what the code looks like?**

Almost every published claim about the security of AI-generated code is really a
claim about what some checker said. The 2026 systematisation of that literature
puts the problem plainly: most benchmarks still score with static, single-CWE,
function-level checks, so a large share of reported "security" is a property of
the checker rather than of the code. That has been said. It has not been
measured.

`soda` measures it. It runs five security oracles against a corpus of 96 Python
implementations whose security labels were **earned by executing an exploit**,
never asserted by an author, and reports how far each oracle's verdict tracks
behaviour rather than form.

## The result

Eight weakness classes, 96 variants, 48 secure and 48 vulnerable, **every label
established by running code** — 0 invalid, 0 disagreements with author intent.

| Oracle | Sensitivity | Specificity | Youden's J |
|---|---|---|---|
| `structural` (AST rules, ours) | 68.8% [54.2, 81.2] | 79.2% [72.9, 83.3] | **+0.479** |
| `pattern` (regex rules, ours) | 75.0% [60.4, 87.5] | 62.5% [52.1, 70.8] | +0.375 |
| `bandit` 1.9.4 | 52.1% [20.8, 83.3] | 75.0% [52.1, 91.7] | +0.271 |
| `semgrep` 1.173.0 `p/security-audit` | 31.2% [8.3, 58.3] | 93.8% [85.4, 100.0] | +0.250 |
| `semgrep` 1.173.0 `p/python` | 20.8% [6.2, 39.6] | 95.8% [91.7, 100.0] | +0.167 |

Brackets are 95% percentile intervals from a bootstrap that resamples **cases**,
not variants, because variants inside a case are not independent draws.

Three things fall out of the per-variant record.

**1. False alarms land on code that merely *looks* dangerous.** Secure variants
come in two kinds: plain ones, and *decoys* that carry the weakness class's
lexical signature without the weakness — the dangerous call written out in a
comment, `md5` used as a cache key in a module that stores passwords with
PBKDF2, `shell=True` with every argument correctly quoted.

| Oracle | Flagged plain secure code | Flagged decoys |
|---|---|---|
| `pattern` | 6.9% (2/29) | **84.2%** (16/19) |
| `structural` | 6.9% (2/29) | **42.1%** (8/19) |
| `bandit` | 13.8% (4/29) | **42.1%** (8/19) |
| `semgrep p/security-audit` | 0.0% (0/29) | 15.8% (3/19) |
| `semgrep p/python` | 0.0% (0/29) | 10.5% (2/19) |

A checker three to twelve times more likely to cry wolf when the *spelling*
changes and the behaviour does not is, to that extent, reading the spelling.

**2. Knowing the weakness is not the same as finding it.** Restricting to cases
where an oracle flagged the textbook form — proving it has a rule for that class —
between **20% and 53%** of behaviourally identical vulnerable variants still got
past it. They differ only in form: an alias, a helper function, `getattr` on a
computed name, a flag arriving through a dict.

**3. Seven vulnerable variants were invisible to all five oracles.** Among them
`v03_sha256_unsalted` and `v04_salted_sha256`, where a *strong* hash is used for
the wrong job. The weakness is that the digest is cheap, which is a property of
what it protects, not of its name — and a name is what these rules match on.

The full report, including per-case tables and every disagreement, is in
[`results/REPORT.md`](results/REPORT.md); the raw record of all 96 variants is in
[`results/audit.json`](results/audit.json).

## Why the labels are executed

The obvious way to build this corpus is to write vulnerable and secure snippets
and label them. That cannot answer the question, because the labels would come
from the same intuitions the checkers encode — *this calls `yaml.load`, so it is
vulnerable* — and the study would measure agreement between two restatements of
one belief.

So every variant is run twice, in its own process:

```
functional contract holds + exploit witness succeeds  ->  vulnerable
functional contract holds + exploit witness fails     ->  secure
functional contract fails                             ->  invalid, excluded
```

A variant is vulnerable because an attack against it *worked*. `s06_escaped_literal`
concatenates user input straight into SQL and is labelled secure, because the
injection is tried and fails. `v04_salted_sha256` uses a modern hash and is
labelled vulnerable, because the password is recovered inside the attacker's
budget. Neither label would survive an author's intuition; both survive
execution.

## Install and run

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev,oracles]"

soda check     # corpus integrity and fingerprint
soda oracles   # which checkers are installed, and their versions
soda truth     # re-earn every label by execution; exits 1 if any label moved
soda audit     # the full run -> results/audit.json + results/REPORT.md
```

`soda audit --no-external` skips bandit and semgrep, which is how CI proves the
pipeline end to end without depending on a rule registry being reachable.

## What is in here

```
corpus/                     8 weakness classes x 12 implementations
  <case>/case.json          CWE, witness description, accepted CWEs, variant manifest
  <case>/harness.py         the functional contract and the exploit witness
  <case>/variants/*.py      the implementations under audit
src/soda/
  groundtruth.py, _probe.py execution in an isolated subprocess
  oracles/                  pattern, structural, bandit, semgrep adapters
  metrics.py                sensitivity, specificity, stealth escape, decoy alarm
  audit.py, report.py, cli.py
PROTOCOL.md                 the method, fixed before the oracles were run
RESEARCH.md                 the write-up: related work, results, threats to validity
```

## Reading this honestly

- This does **not** claim any published benchmark is wrong. It characterises
  *families* of oracle. The `pattern` oracle is a reconstruction written for this
  study and labelled as such, not a copy of anyone's harness.
- It does **not** measure static analysers as static analysers. A tool tuned for
  a low false-positive rate in code review is behaving correctly when it stays
  quiet on an unusual construction. The claim is about what happens when such a
  tool is used as a **benchmark oracle**, where silence is scored as security.
- Semgrep results belong to a **named ruleset**, which is why two are audited
  separately. Changing the ruleset changes the answer, and that is itself the
  finding.
- The corpus is small and hand-built. It is a measurement instrument, not a
  sample of real code; no rate here estimates how often this happens in the wild.

[`PROTOCOL.md`](PROTOCOL.md) states the design, the pre-declared decisions, and
how each of the five documented failure modes of perturbation-based validity
audits is guarded against. [`RESEARCH.md`](RESEARCH.md) states what the numbers
do and do not support.

## Safety

`corpus/` contains deliberately vulnerable code and working exploit witnesses.
They create marker files inside a per-run temporary directory and, for CWE-78,
run a shell command that writes one. No network access, nothing destructive,
nothing outside the temporary directory. See [`SECURITY.md`](SECURITY.md).

## Licence

MIT. If you use this, please cite it — see [`CITATION.cff`](CITATION.cff).
