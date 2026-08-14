# Does the oracle read the code, or the spelling?

### An execution-grounded audit of the security oracles used to score AI-generated code

**Prathamesh Kalamkar** · August 2026 · artifact: this repository ·
results: [`results/audit.json`](results/audit.json), [`results/REPORT.md`](results/REPORT.md)

---

## 1. Summary

A benchmark that reports "model X writes secure code 62% of the time" is
reporting what a checker said 62% of the time. If that checker responds to the
*form* of the code rather than its behaviour, the benchmark is partly measuring
style conformance, and any intervention that shifts style — a prompt, a
fine-tune, a house convention — can move the number without moving the security.

This study measures how much of a security oracle's verdict is behavioural. It
builds a corpus of 96 Python implementations across 8 weakness classes whose
security labels are produced by **running an exploit**, not by an author's
judgement, and scores five oracles against those labels.

**Every oracle scored below Youden's J = 0.48.** The best was a 220-line
syntax-tree matcher written for this study (J = +0.479); the production static
analysers scored between +0.167 and +0.271. False alarms concentrated three- to
twelve-fold on secure code that merely carried the weakness's lexical signature.
Between 20% and 53% of behaviourally identical vulnerable variants escaped
oracles that provably had a rule for the weakness. Seven vulnerable variants
were invisible to all five.

Neither loosening the scoring rule (count any finding) nor tightening it (count
only confident findings) rescued the picture: all three variants of the analysis
sit in a band from J = +0.167 to +0.479.

**A second study, on code nobody here wrote**, takes 140 real fixes to real CVEs
across 65 real projects and asks whether each oracle's verdict changed when the
weakness was actually repaired. It did not, for **92.9% to 98.6%** of them. And
the hand-built corpus turns out to *predict* the real per-class picture (Spearman
ρ = +0.782, 83% agreement on coverage) while scoring the tools **higher** than
reality does in 19 of 30 cells — so the corpus is, if anything, too easy.

## 2. The problem, and why it is not already solved

That security oracles are weak is not a new observation. The 2026 SoK on AI
secure code generation states that most benchmarks still rely on static,
single-CWE, function-level checks, and that a large share of reported security is
therefore a property of the checker. `CWEval` makes the same point when
motivating outcome-driven evaluation: static analysers suffer both false
negatives and false positives because they cannot model semantically equivalent
implementations. `DualGauge` puts it most sharply — secure and vulnerable
implementations are typically indistinguishable on ordinary inputs, so only an
oracle that reasons about execution can separate them.

Three literatures approach this and stop short:

**Test adequacy for functional benchmarks.** `EvalPlus` showed HumanEval's tests
were too thin to catch real defects and augmented them 80-fold; later work
(Liu et al., *JSEP* 2025; mutation-guided regression-suite diagnosis, 2026)
generalised the method. All of it targets *functional* correctness. The security
oracle is a different object: its job is to detect a property that, by
construction, does not change the program's normal output.

**Testing static analysers.** `Statfier` and `StaAgent` test analysers with
semantics-preserving transformations, and there is a body of work on
metamorphic security testing. These evaluate analysers *as analysers*, against
their own documented rule semantics. They do not ask what happens when such a
tool is promoted to the role of benchmark ground truth, where a missing finding
is silently scored as evidence of security.

**Better security benchmarks.** `CWEval`, `SecureAgentBench`/`SecureVibeBench`,
`A.S.E`, and `RealSec-bench` have all moved towards executable tests and
proof-of-concept exploits — the right direction, and this study depends on the
same insight. But they use execution to *build a better oracle*. None of them
turns the instrument around and uses execution to **measure how wrong the
existing oracles are**, which is what a reader needs in order to know how much
of the prior literature to discount.

**The gap.** The claim "reported security is partly a property of the checker"
has been made qualitatively and repeatedly. No located work quantifies it with a
corpus whose labels are independent of any checker, and none separates the two
things that produce a wrong verdict: *not having a rule* and *having a rule that
matches the wrong thing*.

> A note on this section's strength. This is a **rapid** review conducted in a
> single session (14 August 2026), not a systematic one; the queries are recorded
> in §9. The novelty claim it supports is narrow and should be read as such: no
> located work performs this measurement. A forward-citation check and review by
> an experienced researcher are outstanding.

## 3. Design

The full method is in [`PROTOCOL.md`](PROTOCOL.md), fixed before any oracle ran.
The essentials:

**Labels are earned.** Each case declares one functional contract and one exploit
witness. A variant is `vulnerable` iff it satisfies the contract *and* the
exploit succeeds; `secure` iff it satisfies the contract and the exploit fails;
`invalid` — excluded from every rate — if it cannot do its job. Author intent is
recorded separately and never used as a label.

The corpus produced **48 secure, 48 vulnerable, 0 invalid**, with zero
disagreements between intent and execution. Two labels are worth pausing on,
because no author intuition would produce them reliably:

- `cwe089/s06_escaped_literal` concatenates user input directly into a SQL
  string and is labelled **secure** — the injection is attempted and fails,
  because the quoting is correct.
- `cwe916/v04_salted_sha256` uses a modern, unbroken hash with a random salt and
  is labelled **vulnerable** — the password is recovered inside the attacker's
  budget, because SHA-256 is fast.

**Mutations probe specific failures.** Each case has one `canonical` vulnerable
variant (the textbook form) and five that keep the behaviour and change the form:
aliasing, helper indirection, `getattr` on a computed name, a flag arriving
through a dict, an alternative sink, and — most importantly — two that *look
defended* (a blocklist that misses the payload, a guard that only rejects a
leading `..`). Secure variants include *decoys* that carry the class's signature
without the weakness: the dangerous call in a comment, `yaml.load` with
`SafeLoader`, `md5` as a cache key beside PBKDF2 password storage, `random` for
retry jitter beside `secrets` tokens, `shell=True` with correct quoting.

**Attribution is the tool's own claim.** An oracle is never told which weakness
it is being tested for. A finding counts when the CWE identifiers *the tool
attaches to it* intersect a per-case accepted set fixed in advance.

**Uncertainty respects clustering.** Variants within a case share a contract and
an author, so intervals are percentile bootstrap over **cases**, 2000 iterations,
fixed seed.

**The headline statistic is conditional.** *Stealth escape* is computed only over
cases where the oracle flagged the canonical variant — proving it has a rule for
that class — and asks what fraction of the *other* execution-confirmed vulnerable
variants it missed. Without that conditioning, "no rule" and "wrong rule" are
indistinguishable, and only the second is evidence about construct validity.

## 4. Results

Corpus SHA-256 `e3d65a1c…`; Python 3.14.6; bandit 1.9.4; semgrep 1.173.0.

The labels replicate across platforms. The same corpus executed on an Ubuntu CI
runner under Python 3.12 produced the same 48 secure / 48 vulnerable / 0 invalid
split and identical scores for both reconstructed oracles, despite the CWE-78
witness using a different shell payload on each platform. That is a check on the
witnesses, not on the oracles: it says the labels are a property of the code
rather than of the machine that ran it.

### 4.1 Discrimination

| Oracle | Sensitivity | Specificity | Youden's J |
|---|---|---|---|
| `structural` (AST, ours) | 68.8% [54.2, 81.2] | 79.2% [72.9, 83.3] | **+0.479** [+0.354, +0.604] |
| `pattern` (regex, ours) | 75.0% [60.4, 87.5] | 62.5% [52.1, 70.8] | +0.375 [+0.208, +0.542] |
| `bandit` 1.9.4 | 52.1% [20.8, 83.3] | 75.0% [52.1, 91.7] | +0.271 [+0.062, +0.500] |
| `semgrep` `p/security-audit` | 31.2% [8.3, 58.3] | 93.8% [85.4, 100.0] | +0.250 [+0.062, +0.438] |
| `semgrep` `p/python` | 20.8% [6.2, 39.6] | 95.8% [91.7, 100.0] | +0.167 [+0.042, +0.312] |

A perfect oracle scores J = 1.0. On labels established by execution, the best
checker here recovers under half of that, and the two production analysers
recover about a quarter.

The high-specificity, low-sensitivity profile of semgrep is not a defect in
semgrep. It is a tool tuned so that what it says is worth acting on. That is the
right trade for code review and the wrong one for a benchmark oracle, where a
silent tool is read as a clean bill of health.

### 4.2 False alarms follow the spelling

| Oracle | Plain secure flagged | Decoy secure flagged | Ratio |
|---|---|---|---|
| `pattern` | 6.9% (2/29) | 84.2% (16/19) | 12× |
| `structural` | 6.9% (2/29) | 42.1% (8/19) | 6× |
| `bandit` | 13.8% (4/29) | 42.1% (8/19) | 3× |
| `semgrep p/security-audit` | 0.0% (0/29) | 15.8% (3/19) | — |
| `semgrep p/python` | 0.0% (0/29) | 10.5% (2/19) | — |

This is the cleanest evidence in the study. Plain and decoy variants are both
secure — the same witness was run against both and failed against both. They
differ only in whether the source *carries the weakness's signature*. Every
oracle alarms far more often on the decoys.

One secure variant was flagged by **all five** oracles:
`cwe078/s06_shell_true_quoted`, which passes `shell=True` with every argument
quoted for the platform. The witness fires a shell separator at it and the
injection fails. A benchmark using any of these oracles would count that
implementation as insecure.

### 4.3 Having the rule is not finding the weakness

| Oracle | Cases with a rule | Stealth variants | Escaped | Rate |
|---|---|---|---|---|
| `bandit` | 5/8 | 25 | 5 | 20.0% [0.0, 53.3] |
| `pattern` | 8/8 | 40 | 12 | 30.0% [15.0, 47.5] |
| `semgrep p/security-audit` | 3/8 | 15 | 5 | 33.3% [0.0, 60.0] |
| `structural` | 8/8 | 40 | 15 | 37.5% [22.5, 55.0] |
| `semgrep p/python` | 3/8 | 15 | 8 | 53.3% [40.0, 60.0] |

Read the coverage column first. Semgrep's rulesets fired on the canonical form in
only 3 of 8 classes; bandit in 5 of 8. Those gaps are *not* form sensitivity —
they are absence of coverage, and separating them is the point of conditioning.
Within the classes each tool does cover, between a fifth and a half of
behaviourally identical vulnerable code still got through.

### 4.4 Seven variants no oracle saw

| Variant | Why it escapes a form-matching rule |
|---|---|
| `cwe916/v03_sha256_unsalted` | A strong hash doing the wrong job. The weakness is that it is *fast*. |
| `cwe916/v04_salted_sha256` | Salted and modern. Still recovered inside the budget. |
| `cwe916/v06_getattr_dispatch` | `getattr(hashlib, "md" + "5")` — the name never appears. |
| `cwe022/v05_normpath_only` | Normalisation is not containment, but it looks like a defence. |
| `cwe022/v06_helper_indirection` | The join and the `open` live in different functions. |
| `cwe347/v05_swallowed_failure` | Verification is present, correct, and its failure is caught and ignored. |
| `cwe502_yaml/v04_getattr_dispatch` | `getattr(yaml, "unsafe" + "_load")`. |

The first two are the most instructive. No rule that matches on algorithm names
can label them, because there is no weak name in them. The weakness is a property
of the relationship between a primitive and its use, which is exactly the kind of
thing a behavioural witness settles and a pattern cannot.

### 4.5 The conclusion does not depend on the scoring rule

Two pre-planned sensitivity analyses, both reported in the results file:

| Oracle | Primary J | Any finding counts | Confident findings only |
|---|---|---|---|
| `structural` | +0.479 | +0.479 | +0.479 |
| `pattern` | +0.375 | +0.375 | +0.375 |
| `bandit` | +0.271 | +0.312 | +0.229 |
| `semgrep p/security-audit` | +0.250 | +0.250 | +0.250 |
| `semgrep p/python` | +0.167 | +0.167 | +0.167 |

Loosening and tightening move bandit by ±0.04 and change nothing else. There is
no threshold on this axis that turns these oracles into good ones.

Two details inside that table are worth reporting on their own account.

**Bandit files unsafe YAML loading under CWE-20**, not CWE-502. Under the
pre-declared rule that is a miss; under "any finding" it is a detection. A
benchmark harness that filters findings by the CWE it is testing would silently
score a correct detection as a failure to detect. The problem is not the tool's;
it is the harness's assumption that CWE labels are interoperable.

**Bandit flags every CWE-78 variant in the corpus** — all six vulnerable and all
six secure — because it warns on the mere `import subprocess` (B404, low
severity, CWE-78). Its discrimination on that class is exactly zero: J = 0.0.
Restricting to medium-or-above severity turns that class into the best single
result in the study (5/6 and 5/6, J = +0.667). This is directly actionable for
anyone using bandit as an oracle — *and* it costs elsewhere: the same restriction
drops bandit's overall sensitivity from 52.1% to 33.3% and doubles its stealth
escape rate from 20% to 40%.

## 4bis. The production study: 140 real CVE fixes in 65 projects

Everything above rests on a corpus its author also designed. That objection
cannot be answered from inside the corpus, so it is answered from outside it.

**Construction.** For every reviewed GitHub advisory affecting a PyPI package in
the seven covered weakness classes, we take the maintainer's own fix commit and
form one **pair** per Python file it modified: the file at the parent revision,
and the file at the fix. Merge commits are excluded (no single "before"). Tests,
`version.py` and `conftest.py` are excluded. Commits touching more than four such
files are excluded, because a release blob is not a fix. Nothing about which CVEs
exist, which projects they hit, or how they were repaired was chosen by us.

The result: **140 pairs, 102 advisories, 65 repositories**, of which 77 come from
commits that modified exactly one non-test Python file — the `solo` subset, where
the changed file is almost certainly the one that was wrong.

**Detection is low, and it is a floor.**

| Oracle | Detected pre-fix file | `solo` subset |
|---|---|---|
| `bandit` | 29.3% (41/140) | 37.7% (29/77) |
| `structural` | 29.3% (41/140) | 40.3% (31/77) |
| `pattern` | 27.1% (38/140) | 35.1% (27/77) |
| `semgrep p/security-audit` | 7.9% (11/140) | 14.3% (11/77) |
| `semgrep p/python` | 4.3% (6/140) | 6.5% (5/77) |

These are floors because a fix commit may touch files that never carried the bug.
Using the synthetic study as a **coverage control** — restricting to classes where
that oracle demonstrably had a working rule — bandit reaches 46.4% (39/84) and the
rest stay below 30%.

**The result that does not depend on file-level labels.**

Each pair asks a paired question: *did the verdict change when the weakness was
actually repaired?* This needs no assumption about which file carried the bug,
only that the commit repaired something real — which is what the advisory
attests.

| Oracle | caught and cleared | silent throughout | flagged throughout | reversed | fix-blind |
|---|---|---|---|---|---|
| `pattern` | 9 | 101 | 29 | 1 | **92.9%** |
| `bandit` | 6 | 99 | 35 | 0 | **95.7%** |
| `structural` | 5 | 99 | 36 | 0 | **96.4%** |
| `semgrep p/python` | 3 | 134 | 3 | 0 | **97.9%** |
| `semgrep p/security-audit` | 2 | 129 | 9 | 0 | **98.6%** |

Between 130 and 138 of 140 real security fixes produced **no change at all** in
the oracle's verdict. The dominant cell is `silent throughout`: the tool had
nothing to say about either revision. One case is `reversed` — the `pattern`
oracle flagged only `HKUDS/LightRAG`'s *fixed* version of `lightrag/api/auth.py`.

**37 of the 77 single-file fixes were missed by every oracle**, among them
`matrix-org/synapse` `federation_base.py` (CWE-347), `apache/superset`
`config.py` (CWE-89), `gitpython-developers/GitPython` `repo/base.py` (CWE-78),
`ankitects/anki` `mediasrv.py` (CWE-22), `sybrenstuvel/python-rsa` `pkcs1.py` and
`tlsfuzzer/python-ecdsa` `der.py` (CWE-347), `thumbor` `file_loader.py` (CWE-22)
and `keras` `tfsm_layer.py` (CWE-502).

By class, semgrep's two rulesets detected **0 of 35** real path-traversal pairs,
**0 of 26** signature-verification pairs and **0 of 4** randomness pairs; bandit
detected **0 of 26** signature-verification pairs.

### Does the hand-built corpus predict reality?

Over the 30 `(oracle, weakness class)` cells the two studies share, with at least
four real pairs each:

- **83%** agreement (25/30) on whether the oracle detects the class at all
- Spearman **ρ = +0.782** between synthetic and real detection rates
- the real rate is **lower** than the synthetic rate in **19 of 30** cells

The third bullet is the one that answers the objection. A corpus written to
embarrass these tools would score them below their real-world performance. This
one scores them above it — the hand-written mutants are *easier* than what
maintainers actually shipped. The corpus is not adversarial enough, not too
adversarial.

The disagreements are informative rather than awkward. Bandit detects nothing in
the corpus's CWE-502 case but 43% of real CWE-502 pairs, because the corpus case
is YAML — which bandit files under CWE-20, outside the accepted set — while many
real advisories are pickle, which it files under CWE-502. The CWE-attribution
problem of §4.5 reappearing in an independent dataset.

### What the production study cannot support

- **File-level labels are coarse.** A pre-fix file is "vulnerable" only in the
  sense that a commit fixing a CVE of that class changed it. Detection rates are
  floors; the `solo` subset narrows but does not eliminate this.
- **`flagged throughout` is not always blindness.** A file can carry a second,
  unrelated finding of the same class that legitimately survives the fix. Only
  `silent throughout` is unambiguous, and it is the larger cell in every row.
- **Advisory CWE labels are themselves imperfect**, assigned by humans under time
  pressure, and an advisory often carries several. The accepted set is the union,
  which is generous to the tools.
- **Selection.** Only advisories whose fix commit is linked and public, in seven
  classes, in Python. Nothing here estimates a population rate.
- These are **the same tools in a different role**, not a claim that bandit or
  semgrep is bad at code review.

## 5. What this means

**For benchmark authors.** A reported "secure rate" carries the oracle's error
profile inside it, and that profile is not random with respect to how code is
written. Two consequences follow. First, publish the oracle's discrimination on a
labelled corpus alongside the model scores; a model number without an oracle
number is uninterpretable. Second, when a static oracle is unavoidable, report
what its verdicts are conditional on — CWE attribution, severity threshold,
ruleset — because each of those choices moved results here.

**For anyone comparing interventions.** If an intervention changes coding *style*
— and prompts, system instructions, and repository conventions all do — then part
of any measured security change may be a change in how legible the code is to the
checker. Distinguishing the two requires an oracle that reads behaviour. This
matters directly for studies of secure-coding instructions, where the
intervention is precisely a nudge towards a canonical form.

**For tool users.** Nothing here says these analysers are bad at their jobs.
Bandit and semgrep are tuned for a workflow in which a human reads the finding.
The failure is one of *promotion*: moving a code-review aid into the position of
ground truth, where its silence is scored as a positive result.

## 6. Threats to validity

**Construct.** The witness defines the property measured, and it is narrower than
the CWE title — CWE-916 here means "recoverable cheaply offline within a stated
budget", not everything CWE-916 covers. Each witness is described in
`case.json`, and the elapsed times are in the results so the CWE-916 margin
(roughly four orders of magnitude) can be checked rather than trusted.

**Internal.** The corpus was written by one author, who also wrote two of the
five oracles. Those two are labelled as reconstructions and are not the basis of
any claim about a real tool; notably they *outperform* the production tools here,
so the design is not biased towards making checkers look bad. A more serious risk
is that the mutations were chosen with some intuition about what would evade
matching. That is true, and it is why the study reports coverage and conditioning
explicitly instead of a single accuracy number, and why the complete per-variant
record is published.

**A concrete instance, and how it was caught.** The first run of this audit
reported bandit at sensitivity 0.000. That was not bandit; it was this study's
CWE extractor failing on bandit's `{"id": 78, "link": ...}` shape, where the
number never appears beside the letters "CWE". It was found by reading the raw
tool output rather than the audit's summary of it. That is failure mode F2 —
measuring the extraction instead of the tool — occurring in practice, in an audit
explicitly designed against it. It is reported here because it is the strongest
available evidence for why raw records must be published.

**External.** Python only, eight weakness classes, one corpus, pinned tool
versions. Semgrep results belong to named rulesets; two were audited and they
differ. CodeQL — the oracle in much of the published security-generation
literature — is **not** audited here, which is the single largest gap. The rates
are properties of this instrument and do not estimate frequencies in real code.

**Statistical.** Eight cases is a small cluster count; the intervals are wide and
several include values that would change the reading (bandit's stealth escape
interval reaches 0.0). The ordering of the two production analysers is not
established by this data. What the data does support is the aggregate statement:
no oracle approached behavioural discrimination, and false alarms tracked form.

## 7. What would make this stronger

In rough order of value:

1. **Add CodeQL**, and an LLM-as-judge oracle. Both are used as benchmark ground
   truth and neither is covered here. This is now the single largest gap.
2. **Re-score a published benchmark's model outputs** with a behavioural oracle
   and report how much the leaderboard moves. That converts this from a claim
   about oracles into a correction to a specific result.
3. **Sharpen the production labels.** Localise each fix to the changed hunk
   rather than the changed file, so detection becomes an estimate rather than a
   floor. The paired fix-blindness statistic already survives the coarse label;
   detection does not.
4. **Independent methodological review** before any claim of novelty is made in
   public. This is a hard gate in the parent research programme, and it has not
   been passed.

Item 3 in the previous version of this list — *grow and diversify the corpus so
the mutations are not all the author's* — has been superseded rather than
completed. The production study reaches the same conclusion on 140 fixes nobody
here wrote, and the cross-study comparison shows the hand-built corpus predicting
the real per-class picture while being *easier* than it. Enlarging the synthetic
corpus would no longer be the cheapest way to buy confidence.

## 8. Reproducing

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev,oracles]"

# controlled study
soda check && soda truth && soda audit

# production study (needs an authenticated `gh`)
soda production build && soda production fetch && soda production audit
soda production compare
```

Results are comparable only when `environment.corpus_sha256` matches for the
controlled study, or `environment.manifest_sha256` for the production one. The
corpus is deliberately excluded from formatting tools: a variant's lexical form
is the independent variable, and reformatting it silently changes the experiment.

The production study's fetched revisions are not in this repository — they are
other people's code under their own licences. What ships is the manifest that
identifies them and the results computed from them.

## 9. Literature search record

Conducted 14 August 2026, via web search, in one session. This is a rapid review;
it does not support a PRISMA-style claim about database coverage.

Queries: `construct validity security oracle AI code generation benchmark
mutation audit 2026`; `secure code generation benchmark oracle validity false
positives static analysis labels unreliable`; `metamorphic testing static
analysis security detectors semantic preserving transformations evade CWE
detection`; `mutation testing benchmark test suite adequacy code generation
EvalPlus weak test cases security`; `"security oracle" validity measure false
pass false alarm secure code benchmark "semantically equivalent" rewrite study`;
`CodeQL semantic equivalent secure implementations false negatives benchmark
security label brittle coding agent evaluation`; `audit security oracles
benchmarks "ground truth" executable exploit witness mutants measure oracle
sensitivity specificity AI generated code 2026`.

Works positioned against, by role:

| Role | Work |
|---|---|
| States the problem qualitatively | SoK: AI Secure Code Generation ([2606.25195](https://arxiv.org/abs/2606.25195)) |
| Motivates outcome-driven oracles | CWEval ([2501.08200](https://arxiv.org/abs/2501.08200)); DualGauge ([2511.20709](https://arxiv.org/abs/2511.20709)) |
| Executable security benchmarks | SecureAgentBench ([2509.22097](https://arxiv.org/abs/2509.22097)); A.S.E ([2508.18106](https://arxiv.org/abs/2508.18106)); RealSec-bench ([2601.22706](https://arxiv.org/abs/2601.22706)) |
| Functional test adequacy | EvalPlus (NeurIPS 2023); Liu et al. (*JSEP* 2025); mutation-guided regression diagnosis ([2604.01518](https://arxiv.org/abs/2604.01518)) |
| Testing analysers as analysers | StaAgent ([2507.15892](https://arxiv.org/abs/2507.15892)); semantics-preserving mutation operators ([2503.23448](https://arxiv.org/abs/2503.23448)) |
| Analyser landscape | Many Tools, Few Exploitable Vulnerabilities ([2602.18270](https://arxiv.org/abs/2602.18270)) |
| How audits fail | Auditing the Audit ([2607.02586](https://arxiv.org/abs/2607.02586)) — F1–F5 and G1–G6, mapped in `PROTOCOL.md` §6 |
| Why style-shifting interventions matter | When Developer Aid Becomes Security Debt ([2507.09329](https://arxiv.org/abs/2507.09329)) |

## 10. Status

`artifact` — public code and data, no paper. Not submitted, not peer-reviewed,
not a preprint. The results in this repository were produced by the commands in
§8 and can be regenerated from the digests recorded in them.

Two studies, both reproducible: a controlled one over 96 execution-labelled
variants, and a production one over 140 real CVE fixes in 65 projects. They agree
(ρ = +0.782), and the second was collected from sources the author had no hand in.
That is the strongest form the evidence takes at this stage; it is still one
author, seven weakness classes, Python only, and without CodeQL.
