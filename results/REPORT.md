# Security oracle discrimination audit

Generated: 2026-08-14T16:22:17+00:00; Python: 3.14.6; platform: Windows-11-10.0.26200-SP0; corpus SHA-256: e3d65a1cb0593a3c; corpus: 8 cases / 96 variants / secure 48, vulnerable 48, invalid 0.

## Corpus

| CWE | Title | Variants | Accepted CWEs | Witness |
| --- | --- | --- | --- | --- |
| CWE-22 | Path traversal in a document reader | 12 | CWE-22, CWE-23, CWE-36, CWE-73 | A name walking out through an existing subdirectory returns the secret stored beside the root. |
| CWE-78 | OS command injection when invoking an external tool | 12 | CWE-78, CWE-77, CWE-88 | A shell separator appended to the path runs a second command, observed as a marker file. |
| CWE-89 | SQL injection in a user lookup | 12 | CWE-89, CWE-943 | Filter bypass: an unknown username that closes the quoted literal returns the admin row. |
| CWE-330 | Session token drawn from a predictable generator | 12 | CWE-330, CWE-338, CWE-335 | The next token is predicted from one observed token by searching a small window of clock-derived seeds. |
| CWE-347 | Signed session token whose signature is not properly verified | 12 | CWE-347, CWE-345, CWE-287, CWE-807 | An administrator payload with a forged, empty, foreign-key or 'none' signature is accepted. |
| CWE-502 | Unsafe deserialisation of a client-held session blob | 12 | CWE-502 | A pickle whose __reduce__ calls os.mkdir; the directory appearing proves arbitrary construction. |
| CWE-502 | Unsafe deserialisation of a YAML configuration document | 12 | CWE-502 | A !!python/object/apply tag calls os.mkdir during parsing; the directory appearing proves arbitrary construction. |
| CWE-916 | Password stored with a computationally cheap hash | 12 | CWE-916, CWE-327, CWE-328, CWE-326, CWE-759, CWE-760 | Offline recovery within a fixed budget: a precomputed digest table, then 256 dictionary candidates capped at 2 seconds. |

## Oracle scores

| Oracle | Version | Sensitivity | Specificity | Youden J |
| --- | --- | --- | --- | --- |
| structural | soda-structural/ast-1 | 68.8% [54.2, 81.2] | 79.2% [72.9, 83.3] | +0.479 [+0.354, +0.604] |
| pattern | soda-pattern/13-rules | 75.0% [60.4, 87.5] | 62.5% [52.1, 70.8] | +0.375 [+0.208, +0.542] |
| bandit | python.exe -m bandit 1.9.4 | 52.1% [20.8, 83.3] | 75.0% [52.1, 91.7] | +0.271 [+0.062, +0.500] |
| semgrep:p/security-audit | semgrep/1.173.0 config=p/security-audit | 31.2% [8.3, 58.3] | 93.8% [85.4, 100.0] | +0.250 [+0.062, +0.438] |
| semgrep:p/python | semgrep/1.173.0 config=p/python | 20.8% [6.2, 39.6] | 95.8% [91.7, 100.0] | +0.167 [+0.042, +0.312] |

## Form sensitivity

| Oracle | Cases with rule | Stealth variants | Escaped | Stealth escape rate |
| --- | --- | --- | --- | --- |
| structural | 8/8 | 40 | 15 | 37.5% [22.5, 55.0] |
| pattern | 8/8 | 40 | 12 | 30.0% [15.0, 47.5] |
| bandit | 5/8 | 25 | 5 | 20.0% [0.0, 53.3] |
| semgrep:p/security-audit | 3/8 | 15 | 5 | 33.3% [0.0, 60.0] |
| semgrep:p/python | 3/8 | 15 | 8 | 53.3% [40.0, 60.0] |

For semgrep:p/python, the worst result, 8 of 15 behaviourally identical vulnerable variants escaped even though the checker provably had a rule for the weakness.

## False alarms on secure code

| Oracle | Decoy variants flagged | Plain secure variants flagged |
| --- | --- | --- |
| structural | 8/19 (42.1% [31.6, 52.6]) | 2/29 (6.9%) |
| pattern | 16/19 (84.2% [70.0, 95.5]) | 2/29 (6.9%) |
| bandit | 8/19 (42.1% [18.8, 64.7]) | 4/29 (13.8%) |
| semgrep:p/security-audit | 3/19 (15.8% [0.0, 37.5]) | 0/29 (0.0%) |
| semgrep:p/python | 2/19 (10.5% [0.0, 26.3]) | 0/29 (0.0%) |

## Sensitivity analyses

Intervals are computed for the primary analysis only; these are point estimates.

### Any finding counts

Deliberately over-generous: a tool may file a weakness under an identifier the harness is not looking for.

| Oracle | Sensitivity | Specificity | Youden J | vs primary |
| --- | --- | --- | --- | --- |
| structural | 68.8% | 79.2% | +0.479 | +0.000 |
| pattern | 75.0% | 62.5% | +0.375 | +0.000 |
| bandit | 60.4% | 70.8% | +0.312 | +0.042 |
| semgrep:p/security-audit | 31.2% | 93.8% | +0.250 | +0.000 |
| semgrep:p/python | 20.8% | 95.8% | +0.167 | +0.000 |

### Confident findings only

Deliberately strict: a low-severity advisory note lets a checker flag every file in a class and appear sensitive while discriminating nothing. Added after the first run, so it is post-hoc.

| Oracle | Sensitivity | Specificity | Youden J | vs primary |
| --- | --- | --- | --- | --- |
| structural | 68.8% | 79.2% | +0.479 | +0.000 |
| pattern | 75.0% | 62.5% | +0.375 | +0.000 |
| semgrep:p/security-audit | 31.2% | 93.8% | +0.250 | +0.000 |
| bandit | 33.3% | 89.6% | +0.229 | -0.042 |
| semgrep:p/python | 20.8% | 95.8% | +0.167 | +0.000 |

## Per-case detail

### cwe022_path_traversal: CWE-22: Path traversal in a document reader

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 4 | 2 | 5 | 1 | 2/5 |
| pattern | 4 | 2 | 4 | 2 | 2/5 |
| bandit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/security-audit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/python | 0 | 6 | 6 | 0 | 0/0 |

### cwe078_command_injection: CWE-78: OS command injection when invoking an external tool

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 4 | 2 | 5 | 1 | 2/5 |
| pattern | 6 | 0 | 4 | 2 | 0/5 |
| bandit | 6 | 0 | 0 | 6 | 0/5 |
| semgrep:p/security-audit | 4 | 2 | 5 | 1 | 2/5 |
| semgrep:p/python | 4 | 2 | 5 | 1 | 2/5 |

### cwe089_sql_injection: CWE-89: SQL injection in a user lookup

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 5 | 1 | 4 | 2 | 1/5 |
| pattern | 4 | 2 | 3 | 3 | 2/5 |
| bandit | 5 | 1 | 4 | 2 | 1/5 |
| semgrep:p/security-audit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/python | 0 | 6 | 6 | 0 | 0/0 |

### cwe330_predictable_token: CWE-330: Session token drawn from a predictable generator

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 6 | 0 | 5 | 1 | 0/5 |
| pattern | 5 | 1 | 4 | 2 | 1/5 |
| bandit | 6 | 0 | 5 | 1 | 0/5 |
| semgrep:p/security-audit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/python | 0 | 6 | 6 | 0 | 0/0 |

### cwe347_signature_verification: CWE-347: Signed session token whose signature is not properly verified

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 3 | 3 | 5 | 1 | 3/5 |
| pattern | 5 | 1 | 5 | 1 | 1/5 |
| bandit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/security-audit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/python | 0 | 6 | 6 | 0 | 0/0 |

### cwe502_session_blob: CWE-502: Unsafe deserialisation of a client-held session blob

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 4 | 2 | 5 | 1 | 2/5 |
| pattern | 5 | 1 | 4 | 2 | 1/5 |
| bandit | 6 | 0 | 4 | 2 | 0/5 |
| semgrep:p/security-audit | 6 | 0 | 4 | 2 | 0/5 |
| semgrep:p/python | 0 | 6 | 6 | 0 | 0/0 |

### cwe502_yaml_deserialization: CWE-502: Unsafe deserialisation of a YAML configuration document

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 5 | 1 | 4 | 2 | 1/5 |
| pattern | 5 | 1 | 2 | 4 | 1/5 |
| bandit | 0 | 6 | 6 | 0 | 0/0 |
| semgrep:p/security-audit | 3 | 3 | 6 | 0 | 3/5 |
| semgrep:p/python | 3 | 3 | 6 | 0 | 3/5 |

### cwe916_password_hashing: CWE-916: Password stored with a computationally cheap hash

| Oracle | TP | FN | TN | FP | Stealth escaped/total |
| --- | --- | --- | --- | --- | --- |
| structural | 2 | 4 | 5 | 1 | 4/5 |
| pattern | 2 | 4 | 4 | 2 | 4/5 |
| bandit | 2 | 4 | 5 | 1 | 4/5 |
| semgrep:p/security-audit | 2 | 4 | 6 | 0 | 0/0 |
| semgrep:p/python | 3 | 3 | 5 | 1 | 3/5 |

## Disagreements worth reading

| Case | Variant | Label | Flagged by | Not flagged by |
| --- | --- | --- | --- | --- |
| cwe022_path_traversal | s04_comment_decoy | secure | pattern | bandit, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe022_path_traversal | s06_allowlist | secure | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe022_path_traversal | v01_join | vulnerable | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe022_path_traversal | v02_concat | vulnerable | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe022_path_traversal | v03_pathlib | vulnerable | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe022_path_traversal | v04_prefix_check | vulnerable | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe022_path_traversal | v05_normpath_only | vulnerable | none | bandit, pattern, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe022_path_traversal | v06_helper_indirection | vulnerable | none | bandit, pattern, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | s01_list_argv | secure | bandit | pattern, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | s02_check_output | secure | bandit | pattern, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | s03_shell_false_explicit | secure | bandit | pattern, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | s04_comment_decoy | secure | bandit, pattern | semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | s05_helper_indirection | secure | bandit | pattern, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | s06_shell_true_quoted | secure | bandit, pattern, semgrep:p/python, semgrep:p/security-audit, structural | none |
| cwe078_command_injection | v03_kwargs_shell | vulnerable | bandit, pattern | semgrep:p/python, semgrep:p/security-audit, structural |
| cwe078_command_injection | v04_os_popen | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe078_command_injection | v05_shell_flag_var | vulnerable | bandit, pattern, semgrep:p/python, semgrep:p/security-audit | structural |
| cwe089_sql_injection | s03_fstring_static_table | secure | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe089_sql_injection | s04_comment_decoy | secure | pattern | bandit, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe089_sql_injection | s06_escaped_literal | secure | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe089_sql_injection | v01_fstring | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe089_sql_injection | v02_percent_format | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe089_sql_injection | v03_concat | vulnerable | bandit, structural | pattern, semgrep:p/python, semgrep:p/security-audit |
| cwe089_sql_injection | v04_str_format | vulnerable | pattern | bandit, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe089_sql_injection | v05_helper_indirection | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe089_sql_injection | v06_getattr_dispatch | vulnerable | bandit, structural | pattern, semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | s04_comment_decoy | secure | pattern | bandit, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe330_predictable_token | s05_secrets_with_random_jitter | secure | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | v01_seeded_random | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | v02_global_seed | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | v03_choice_alphabet | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | v04_getattr_dispatch | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | v05_helper_indirection | vulnerable | bandit, pattern, structural | semgrep:p/python, semgrep:p/security-audit |
| cwe330_predictable_token | v06_module_alias | vulnerable | bandit, structural | pattern, semgrep:p/python, semgrep:p/security-audit |
| cwe347_signature_verification | s04_equality_compare | secure | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe347_signature_verification | v01_no_verification | vulnerable | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe347_signature_verification | v02_verify_disabled | vulnerable | pattern | bandit, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe347_signature_verification | v03_alg_none | vulnerable | pattern | bandit, semgrep:p/python, semgrep:p/security-audit, structural |
| cwe347_signature_verification | v04_length_check_only | vulnerable | pattern, structural | bandit, semgrep:p/python, semgrep:p/security-audit |
| cwe347_signature_verification | v05_swallowed_failure | vulnerable | none | bandit, pattern, semgrep:p/python, semgrep:p/security-audit, structural |

27 additional disagreements omitted.
