# Security policy

This repository contains deliberately vulnerable code under `corpus/`. It is research material and must never be imported by anything other than the audit harness.

The executable witnesses create marker files and directories inside a separate temporary directory for each run. For CWE-78, a witness executes a shell command that writes such a marker. The witnesses require no network access, perform no destructive operations, and create no persistence outside the temporary directory.

Security findings about `soda` itself—the audit harness, not the corpus—can be reported by opening an issue.

