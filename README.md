# Security Oracle Discrimination Audit (`soda`)

**When a security oracle changes its verdict, is it responding to what the code
does, or to what the code looks like?**

Almost every published claim about the security of AI-generated code is really a
claim about what some checker said. The 2026 systematisation of that literature
puts the problem plainly: most benchmarks still score with static, single-CWE,
function-level checks, so a large share of reported "security" is a property of
the checker rather than of the code. That has been said. It has not been
measured.

`soda` measures it, twice.

- **A controlled study.** Five security oracles against 96 Python implementations
  whose security labels were **earned by executing an exploit**, never asserted by
  an author.
- **A production study.** The same five oracles against **140 real fixes to real
  CVEs in 65 real projects** — aiohttp, Django, Synapse, superset, GitPython,
  Anki, thumbor, python-rsa — where the label comes from a reviewed advisory and
  the maintainer's own patch, and no part of it was chosen by us.

The second exists because the first has an obvious objection: its author also
chose the mutations. The answer is in §"Did the corpus predict reality?" below.

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

## The production study: 140 real CVE fixes

Each observation is one Python file at two revisions: immediately **before** a
security fix, and **at** the fix. A reviewed GitHub advisory says the project had
a weakness of a given class; the maintainer's own commit is what they did about
it. We chose none of it.

The headline is not detection. It is that **the tools mostly cannot tell the two
revisions apart.**

| Oracle | Detected the vulnerable file | Fixes that changed *nothing* in its verdict |
|---|---|---|
| `bandit` | 29.3% (41/140) | **95.7%** |
| `structural` | 29.3% (41/140) | **96.4%** |
| `pattern` | 27.1% (38/140) | **92.9%** |
| `semgrep p/security-audit` | 7.9% (11/140) | **98.6%** |
| `semgrep p/python` | 4.3% (6/140) | **97.9%** |

Read the right-hand column carefully. For between 130 and 138 of 140 real
security fixes, the oracle said exactly the same thing before and after. Whatever
it is tracking, it is not the presence of the weakness that was repaired.

That column needs no assumption about which file carried the bug — only that the
commit fixed something real, which is what the advisory attests. Detection rates
do depend on that assumption, so they are reported as **floors**, alongside a
`solo` subset of 77 single-file fix commits where the changed file is almost
certainly the one that was wrong (detection there: 6.5%–40.3%).

**37 of those 77 single-file fixes were missed by every one of the five oracles**,
including `matrix-org/synapse` (signature verification), `apache/superset` (SQL
injection), `GitPython` (command injection), `ankitects/anki` (path traversal) and
`sybrenstuvel/python-rsa` (signature verification).

Full report: [`results/PRODUCTION.md`](results/PRODUCTION.md). Raw per-pair
records: [`results/production.json`](results/production.json).

## Did the corpus predict reality?

Yes — which is the real answer to "you designed the mutants to evade."

Comparing the two studies over the 30 `(oracle, weakness class)` cells they share:

- **83%** agreement (25/30) on whether an oracle detects a class *at all*
- Spearman **ρ = +0.782** between the synthetic and real detection rates
- The real rate is **lower** than the synthetic rate in **19 of 30** cells

The last line is the one that settles it. A corpus built to embarrass these tools
would score them *below* their real-world performance. This one scores them
*above* it: the hand-written mutants turn out to be easier than the code
maintainers actually shipped.

See [`results/CROSS_STUDY.md`](results/CROSS_STUDY.md), regenerated by
`soda production compare`.

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

The production study needs an authenticated `gh` CLI, because it reads the GitHub
advisory database and fetches file revisions:

```bash
soda production build     # query advisories -> production/manifest.json
soda production fetch     # download the pre/post revisions into production/cache
soda production audit     # -> results/production.json + results/PRODUCTION.md
soda production compare   # -> results/CROSS_STUDY.md
```

The fetched revisions are **not** in this repository. They are other people's code
under their own licences, so what ships is the manifest that identifies them
(advisory, repository, commit, path) and the results — never the source. `soda
production fetch` reconstructs the cache, and `manifest_sha256` in a results file
pins the exact set of revisions it was computed from.

`soda audit --no-external` skips bandit and semgrep, which is how CI proves the
pipeline end to end without depending on a rule registry being reachable.

## What is in here

```
corpus/                     8 weakness classes x 12 implementations
  <case>/case.json          CWE, witness description, accepted CWEs, variant manifest
  <case>/harness.py         the functional contract and the exploit witness
  <case>/variants/*.py      the implementations under audit
production/manifest.json    140 real CVE fix pairs: advisory, repo, commit, path
src/soda/
  groundtruth.py, _probe.py execution in an isolated subprocess
  oracles/                  pattern, structural, bandit, semgrep adapters
  cwe.py                    the accepted-CWE table both studies score against
  metrics.py                sensitivity, specificity, stealth escape, decoy alarm
  production/collect.py     advisories -> fix commits -> before/after revisions
  production/audit.py       detection and fix blindness on real patches
  production/crossstudy.py  does the corpus predict reality?
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
