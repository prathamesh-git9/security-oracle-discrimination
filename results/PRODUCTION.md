# Security oracles against real CVE fixes

Generated: 2026-08-14T17:32:59+00:00; Python: 3.14.6; platform: Windows-11-10.0.26200-SP0; manifest SHA-256: e2ee697153a6d6fe; dataset: 140 pairs (77 solo), 102 advisories, 65 repositories.

## Dataset

| Weakness class | Pairs |
| --- | --- |
| CWE-22 | 35 |
| CWE-78 | 29 |
| CWE-89 | 36 |
| CWE-330 | 4 |
| CWE-347 | 26 |
| CWE-502 | 14 |
| CWE-916 | 1 |

The dataset represents 65 distinct repositories.

## Detection on real vulnerable code

| Oracle | Version | Pairs | Detected | Detection rate | Solo pairs | Solo detected | Solo rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| bandit | python.exe -m bandit 1.9.4 | 140 | 41 | 29.3% | 77 | 29 | 37.7% |
| structural | soda-structural/ast-1 | 140 | 41 | 29.3% | 77 | 31 | 40.3% |
| pattern | soda-pattern/13-rules | 140 | 38 | 27.1% | 77 | 27 | 35.1% |
| semgrep:p/security-audit | semgrep/1.173.0 config=p/security-audit | 140 | 11 | 7.9% | 77 | 11 | 14.3% |
| semgrep:p/python | semgrep/1.173.0 config=p/python | 140 | 6 | 4.3% | 77 | 5 | 6.5% |

Detection rates across oracles ranged from 4.3% to 29.3%; because a fix commit may touch files that never carried the bug, these rates are floors rather than estimates.

## Fix blindness

| Oracle | Caught and cleared | Silent throughout | Flagged throughout | Reversed | Fix-blind rate |
| --- | --- | --- | --- | --- | --- |
| semgrep:p/security-audit | 2 | 129 | 9 | 0 | 98.6% |
| semgrep:p/python | 3 | 134 | 3 | 0 | 97.9% |
| structural | 5 | 99 | 36 | 0 | 96.4% |
| bandit | 6 | 99 | 35 | 0 | 95.7% |
| pattern | 9 | 101 | 29 | 1 | 92.9% |

### Solo fixes

| Oracle | Caught and cleared | Silent throughout | Flagged throughout | Reversed | Fix-blind rate |
| --- | --- | --- | --- | --- | --- |
| semgrep:p/security-audit | 2 | 66 | 9 | 0 | 97.4% |
| semgrep:p/python | 3 | 72 | 2 | 0 | 96.1% |
| structural | 4 | 46 | 27 | 0 | 94.8% |
| bandit | 6 | 48 | 23 | 0 | 92.2% |
| pattern | 4 | 49 | 23 | 1 | 93.5% |

For semgrep:p/security-audit, the worst result, 138 of 140 real security fixes produced no change in its verdict. One verdict was reversed: the oracle flagged only the maintainer's fixed version.

## Per weakness class

| Weakness class | bandit | pattern | semgrep:p/python | semgrep:p/security-audit | structural |
| --- | --- | --- | --- | --- | --- |
| CWE-22 | 4/35 | 2/35 | 0/35 | 0/35 | 5/35 |
| CWE-78 | 11/29 | 12/29 | 4/29 | 3/29 | 5/29 |
| CWE-89 | 19/36 | 12/36 | 1/36 | 5/36 | 24/36 |
| CWE-330 | 2/4 | 2/4 | 0/4 | 0/4 | 2/4 |
| CWE-347 | 0/26 | 5/26 | 0/26 | 0/26 | 2/26 |
| CWE-502 | 6/14 | 5/14 | 0/14 | 3/14 | 3/14 |
| CWE-916 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |

## Fixes every oracle missed

| Repository | Path | CWEs | GHSA |
| --- | --- | --- | --- |
| Adyen/adyen-python-api-library | Adyen/util.py | CWE-347 | GHSA-f3q4-ggfp-jv34 |
| HKUDS/LightRAG | lightrag/api/auth.py | CWE-347 | GHSA-8ffj-4hx4-9pgf |
| MervinPraison/PraisonAI | src/praisonai/praisonai/cli/features/mcp.py | CWE-78 | GHSA-9qhq-v63v-fv3j |
| WaterFutures/EPyT-Flow | epyt_flow/serialization.py | CWE-502 | GHSA-74vm-8frp-7w68 |
| aliasrobotics/cai | src/cai/tools/reconnaissance/filesystem.py | CWE-78 | GHSA-jfpc-wj3m-qw2m |
| ankitects/anki | qt/aqt/mediasrv.py | CWE-22 | GHSA-869j-r97x-hx2g |
| ansible/ansible | lib/ansible/template/__init__.py | CWE-330 | GHSA-r6h7-5pq2-j77h |
| apache/superset | superset/config.py | CWE-89 | GHSA-92qf-8gh3-gwcm |
| apragacz/django-rest-registration | rest_registration/verification.py | CWE-347 | GHSA-p3w6-jcg4-52xh |
| benbusby/whoogle-search | app/models/config.py | CWE-78 | GHSA-2689-cw26-6cpj |
| dep0we/atomic-agents-stack | atomic_agents/dashboard/serve.py | CWE-22 | GHSA-rm43-82j9-r4mj |
| dgtlmoon/changedetection.io | changedetectionio/flask_app.py | CWE-22 | GHSA-9jj8-v89v-xjvw |
| django/django | django/db/backends/postgresql/compiler.py | CWE-89 | GHSA-rqw2-ghq9-44m7 |
| eosphoros-ai/DB-GPT | dbgpt/app/openapi/api_v1/editor/api_editor_v1.py | CWE-89 | GHSA-7gj6-22m4-qfhx |
| facelessuser/pymdown-extensions | pymdownx/b64.py | CWE-22 | GHSA-9xwg-3r6f-jcx2 |
| gitpython-developers/GitPython | git/objects/submodule/base.py | CWE-22 | GHSA-hmq2-w58f-27jc |
| gitpython-developers/GitPython | git/repo/base.py | CWE-78 | GHSA-6p8h-3wgx-97gf |
| gradio-app/gradio | gradio/oauth.py | CWE-330 | GHSA-pfjf-5gxr-995x |
| jahlives/openssl_encrypt | openssl_encrypt/modules/key_bundle.py | CWE-347 | GHSA-8h88-gxp3-j7pg |
| keras-team/keras | keras/src/export/tfsm_layer.py | CWE-502 | GHSA-4f3f-g24h-fr8m |
| keras-team/keras | keras/src/saving/file_editor.py | CWE-22 | GHSA-m8wh-29wm-52mv |
| keras-team/keras | keras/src/saving/saving_lib.py | CWE-22 | GHSA-gh82-f9x8-5frx |
| koxudaxi/datamodel-code-generator | jsonschema.py | CWE-22 | GHSA-8359-h9fx-j6v9 |
| koxudaxi/datamodel-code-generator | src/datamodel_code_generator/parser/xmlschema.py | CWE-22 | GHSA-442q-2j6p-642g |
| langchain-ai/langgraph | libs/checkpoint/langgraph/cache/base/__init__.py | CWE-502 | GHSA-mhr3-j7m5-c7c9 |
| lepture/mistune | src/mistune/directives/include.py | CWE-22 | GHSA-r4rv-85jg-w4mf |
| matrix-org/synapse | synapse/federation/federation_base.py | CWE-347 | GHSA-fmvh-rvq5-hhjx |
| mlflow/mlflow | mlflow/pyfunc/mlserver.py | CWE-78 | GHSA-rvhj-8chj-8v3c |
| pgadmin-org/pgadmin4 | web/pgadmin/tools/import_export/__init__.py | CWE-78, CWE-89 | GHSA-j74f-g7vx-fh4x |
| pgadmin-org/pgadmin4 | web/pgadmin/tools/maintenance/__init__.py | CWE-89 | GHSA-hp84-p2gq-6fvr |

51 additional pairs omitted.
