# Protocol

This document fixes the method. It was written before the oracles were run, and
the decisions it records — the corpus, the witnesses, the accepted CWE sets, the
statistics — are the ones the results were produced under. Where a decision was
made for convenience rather than principle, it says so.

## 1. The question

Published claims about the security of AI-generated code are almost always
claims about what an oracle said. The 2026 systematisation of this literature
states the problem plainly: most benchmarks still score with static, single-CWE,
function-level checks, so "a large share of reported *security* is a property of
the checker rather than of the code."

That is a statement about validity, and it has been made qualitatively. This
study asks it quantitatively:

> **When a security oracle changes its verdict, is it responding to what the code
> does, or to what the code looks like?**

Two sub-questions follow, and they are deliberately kept apart:

- **RQ1 (diagnostic).** Given an oracle that demonstrably has a rule for a
  weakness class, how often does a behaviourally identical instance of that
  weakness escape it purely by being written differently?
- **RQ2 (invariance).** How often does an oracle report a weakness in code that
  carries the class's lexical signature but not the weakness?

## 2. Why the labels are executed rather than written down

The obvious way to build this corpus is to write vulnerable and secure snippets
and label them. That approach cannot answer the question, because the labels
would come from the same intuitions the checkers encode — "this uses `yaml.load`,
so it is vulnerable" — and the study would measure agreement between two
restatements of one belief.

So every label here is earned:

| functional contract | exploit witness | label |
|---|---|---|
| holds | succeeds | `vulnerable` |
| holds | fails | `secure` |
| fails | — | `invalid`, excluded from every reported rate |

A variant is `vulnerable` because an attack against it worked, and `secure`
because the same attack was tried and did not. The functional gate matters as
much as the witness: code that does not do its job is not evidence about
security, and excluding it stops a broken mutant from being scored as a clean
detection.

Author intent is recorded separately, in each variant's `declared` field, and is
never used as a label. It exists so that intent and outcome can be compared. Any
disagreement is reported rather than reconciled.

### What each witness actually proves

A witness defines the operational property being measured, and that definition is
narrower than the CWE title. This is a feature — it is what makes the label
falsifiable — but it must be read literally:

| Case | The witness proves |
|---|---|
| CWE-89 | An unknown username that closes the quoted literal returns the admin row. |
| CWE-78 | A shell separator in a path causes a second command to run. |
| CWE-502 (YAML) | A `!!python/object/apply` tag calls `os.mkdir` during parsing. |
| CWE-502 (session) | A pickle whose `__reduce__` calls `os.mkdir` is decoded. |
| CWE-22 | A name walking out through a subdirectory returns a secret beside the root. |
| CWE-916 | The stored password is recovered within a fixed offline budget. |
| CWE-330 | The next token is predicted from one observed token. |
| CWE-347 | A forged administrator payload is accepted. |

The CWE-916 witness is the only one with a tunable threshold: a precomputed
digest table, then 256 dictionary candidates abandoned after two seconds of wall
clock. Cheap schemes finish that scan in microseconds; the deliberately slow ones
would need tens of seconds. The separation is about four orders of magnitude, so
the threshold is not a close call, and the elapsed time is recorded in the results
so a reader can check that for themselves.

## 3. The mutation families

Each case holds one contract and twelve implementations of it. They are not
random perturbations; each one probes a specific way an oracle can be wrong.

**Vulnerable variants.** One is `canonical`: the textbook form, the one every
tutorial warns about. The other five keep the same behaviour and change the form
— an alias, a helper function, `getattr` on a computed name, a flag arriving
through a variable or a dict, a different sink with the same effect. Two of them
look *defended*: a blocklist that misses the payload, a check that only rejects a
leading `..`. Those are the ones that matter most in practice, because they are
what real insecure code looks like.

**Secure variants.** Some are the obvious correct answer. The rest are decoys,
flagged as such in the manifest, and each carries the weakness class's signature
without the weakness:

- the dangerous form written out verbatim **in a comment**;
- the dangerous API called with safe arguments (`yaml.load(..., Loader=SafeLoader)`);
- the dangerous API used for a **different, legitimate purpose** (`md5` as a cache
  key in a module that stores passwords with PBKDF2; `random` for retry jitter in
  a module that draws tokens from `secrets`);
- a construction that is lexically identical to the weakness but semantically
  safe (SQL built by concatenation through correct escaping; `shell=True` with
  every argument quoted for the platform).

The decoys are the invariance probes for RQ2. They are also the honest half of
the study: a checker that flags them is not malfunctioning, it is doing what it
was built to do, and the question is whether that is what a benchmark should be
scoring models on.

## 4. Attributing a finding to a weakness class

An oracle is never told which weakness it is being tested for. It sees files.

A finding counts as detection when the CWE identifiers **the tool itself attaches
to that finding** intersect the case's `accept_cwes` set. Those sets were fixed in
`case.json` before any oracle ran, and they are deliberately generous, because
tools label the same weakness with neighbouring identifiers — a cheap password
digest is CWE-916 to one tool and CWE-327 to another. Scoring on an exact string
would measure taxonomy agreement rather than detection.

Every finding is also recorded as `flagged_any`, so a reader can see when a tool
noticed something but filed it elsewhere.

## 5. Statistics

Over variants whose label was established (`invalid` excluded):

- **Sensitivity** — vulnerable variants flagged / vulnerable variants.
- **Specificity** — secure variants not flagged / secure variants.
- **Youden's J** — sensitivity + specificity − 1. Reported because it summarises
  the pair without asserting an exchange rate between the two error types.
- **Stealth escape rate** *(RQ1, the headline)* — restricted to cases where the
  oracle flagged the `canonical` vulnerable variant, and therefore provably has a
  rule for that class: the fraction of the *other* execution-confirmed vulnerable
  variants it missed. The canonical variant is excluded from its own denominator.
- **Decoy alarm rate** *(RQ2)* — decoy secure variants flagged / decoy secure
  variants, reported separately from the alarm rate on plain secure variants.

The conditioning in stealth escape is the point of the design. Without it,
"this tool has no rule for CWE-347" and "this tool has a rule for CWE-347 and is
reading the wrong thing" produce the same number, and only the second is evidence
about construct validity.

**Uncertainty.** Variants inside a case share a contract, a witness and an
author, so they are not independent draws. Intervals are percentile bootstrap
over **cases**, resampling whole cases with their variants attached, 2000
iterations, seed fixed at 20260814.

### Secondary analyses, and which of them is post-hoc

Two alternative scoring rules are reported beside the primary one. Neither is a
result; both exist so a reader can see that the conclusion does not rest on the
detection rule.

- **"any finding counts"** — planned with the primary analysis, because CWE
  labels were expected to disagree between tools.
- **"confident findings only"** (severity medium or above) — **added after the
  first run**, and it is post-hoc. It was prompted by an observation, not a
  hypothesis: bandit flagged every variant in the CWE-78 case, secure and
  vulnerable alike, because it warns on the mere import of `subprocess`. The
  honest reading of a post-hoc analysis is that it generates a question rather
  than answering one, and it is labelled as such wherever it appears.

Intervals are computed for the primary analysis only. The secondary analyses are
reported as point estimates.

## 6. Guards against auditing badly

A perturbation-based validity audit can manufacture its own conclusion. The 2026
"Auditing the Audit" analysis names five ways (F1–F5) and proposes a six-point
disclosure gate (G1–G6). Since this study *is* such an audit, each is addressed
explicitly.

| Failure mode | How this design answers it |
|---|---|
| **F1** perturbation that is silently a no-op | Every variant is a distinct file; `soda check` fails if any two are byte-identical; `corpus_sha256` pins the exact bytes that produced a result. |
| **F2** measuring the extraction rather than the behaviour | Detection is the tool's own CWE claim against a pre-declared accepted set, not our reading of its rule catalogue. |
| **F3** scoring that diverges from the stated protocol | Labels come from an independent subprocess that never sees an oracle; the complete per-variant record table is published in the results file, so every reported rate can be recomputed from raw data. |
| **F4** broken pairing in uncertainty | Cluster bootstrap over cases, keeping each case's variants together. |
| **F5** archetype mismatch | The diagnostic statistics (sensitivity, stealth escape) and the invariance statistics (specificity, decoy alarm) are reported separately and never blended into a single accuracy figure. |

| Gate | Status |
|---|---|
| **G1** scorer-faithful audit | Met — tools' own claims, raw records published. |
| **G2** above-baseline original | Met — stealth escape is conditioned on detecting the canonical variant. |
| **G3** non-trivial denominator | Met — `invalid` variants excluded; every denominator (`stealth_total`, `cases_with_rule`/`cases_total`, `decoy_total`) is reported next to its rate. |
| **G4** paired uncertainty | Met — cluster bootstrap by case. |
| **G5** archetype disclosure | Met — see F5. |
| **G6** repair-regression | Met by construction — the behavioural reference standard scores sensitivity 1.0 and specificity 1.0 on this corpus, because it *is* the label. That is a tautology, and it is the necessary one: it shows the corpus admits a perfect scorer, so the errors reported here are properties of the checkers rather than of the corpus being unreasonably hard. |

## 7. What this study does not claim

- It does **not** claim any published benchmark is wrong. It characterises
  *families* of oracle, one of which (the text matcher) is a reconstruction
  written for this study, clearly labelled as such and not a copy of any
  particular harness.
- It does **not** measure static analysers as static analysers. A tool tuned for
  low false-positive rates in a code-review workflow is behaving correctly when
  it stays quiet on an unusual construction. The claim is about what happens when
  such a tool is used as a *benchmark oracle*, where silence is scored as
  security.
- It does **not** generalise beyond Python, beyond these eight weakness classes,
  or beyond the pinned tool versions recorded in each results file.
- The corpus is **hand-built and small** (8 cases, 96 variants). It is a
  measurement instrument, not a sample of real-world code, and no rate here
  should be read as an estimate of how often this happens in the wild.

## 8. Reproducing a result

```
python -m venv .venv
.venv/bin/pip install -e ".[dev,oracles]"
soda check     # corpus integrity + fingerprint
soda truth     # every label, re-earned by execution
soda audit     # the full run, writing results/audit.json and results/REPORT.md
```

A results file records the Python version, the platform, the corpus SHA-256 and
each oracle's self-reported version. Two results files are comparable only when
the corpus digest matches.
