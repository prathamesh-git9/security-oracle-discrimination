# Does the hand-built corpus predict real CVEs?

The synthetic study chose its own mutations. Nobody chose which CVEs exist, which projects they affect, or how maintainers fixed them. If the two agree per weakness class, the corpus is measuring the oracles rather than its author.

Compared over **30 (oracle, class) cells** with at least 4 real pairs each.

- Agreement on whether the oracle detects the class at all: **25/30 (83%)**
- Spearman rank correlation between detection rates: **+0.782**
- Cells where the real rate is *lower* than the synthetic rate: **19/30**

The last line is the one that answers the objection. A corpus built to embarrass these tools would score them below their real-world performance. This one scores them above it: the hand-written mutants are easier than the code maintainers actually shipped.

| Oracle | Class | Synthetic | Rate | Production | Rate |
| --- | --- | --- | --- | --- | --- |
| bandit | CWE-22 | 0/6 | 0% | 4/35 | 11% |
| bandit | CWE-330 | 6/6 | 100% | 2/4 | 50% |
| bandit | CWE-347 | 0/6 | 0% | 0/26 | 0% |
| bandit | CWE-502 | 0/6 | 0% | 6/14 | 43% |
| bandit | CWE-78 | 6/6 | 100% | 11/29 | 38% |
| bandit | CWE-89 | 5/6 | 83% | 19/36 | 53% |
| pattern | CWE-22 | 4/6 | 67% | 2/35 | 6% |
| pattern | CWE-330 | 5/6 | 83% | 2/4 | 50% |
| pattern | CWE-347 | 5/6 | 83% | 5/26 | 19% |
| pattern | CWE-502 | 5/6 | 83% | 5/14 | 36% |
| pattern | CWE-78 | 6/6 | 100% | 12/29 | 41% |
| pattern | CWE-89 | 4/6 | 67% | 12/36 | 33% |
| semgrep:p/python | CWE-22 | 0/6 | 0% | 0/35 | 0% |
| semgrep:p/python | CWE-330 | 0/6 | 0% | 0/4 | 0% |
| semgrep:p/python | CWE-347 | 0/6 | 0% | 0/26 | 0% |
| semgrep:p/python | CWE-502 | 3/6 | 50% | 0/14 | 0% |
| semgrep:p/python | CWE-78 | 4/6 | 67% | 4/29 | 14% |
| semgrep:p/python | CWE-89 | 0/6 | 0% | 1/36 | 3% |
| semgrep:p/security-audit | CWE-22 | 0/6 | 0% | 0/35 | 0% |
| semgrep:p/security-audit | CWE-330 | 0/6 | 0% | 0/4 | 0% |
| semgrep:p/security-audit | CWE-347 | 0/6 | 0% | 0/26 | 0% |
| semgrep:p/security-audit | CWE-502 | 3/6 | 50% | 3/14 | 21% |
| semgrep:p/security-audit | CWE-78 | 4/6 | 67% | 3/29 | 10% |
| semgrep:p/security-audit | CWE-89 | 0/6 | 0% | 5/36 | 14% |
| structural | CWE-22 | 4/6 | 67% | 5/35 | 14% |
| structural | CWE-330 | 6/6 | 100% | 2/4 | 50% |
| structural | CWE-347 | 3/6 | 50% | 2/26 | 8% |
| structural | CWE-502 | 5/6 | 83% | 3/14 | 21% |
| structural | CWE-78 | 4/6 | 67% | 5/29 | 17% |
| structural | CWE-89 | 5/6 | 83% | 24/36 | 67% |

## How to read a disagreement

The cells that disagree are informative rather than embarrassing. Bandit detects nothing in the corpus's CWE-502 case but 43% of real CWE-502 pairs, because the corpus case is YAML -- which bandit files under CWE-20, outside the accepted set -- while many real advisories are pickle, which it files under CWE-502. That is the CWE-attribution problem showing up twice in two independent datasets.
