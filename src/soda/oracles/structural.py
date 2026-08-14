"""A structural oracle: syntax-tree rules with import-alias resolution.

This is the second reconstruction, and it is deliberately a step up from
:mod:`soda.oracles.pattern`. It parses the file, so comments and strings can no
longer trigger it, and it follows ``import x as y`` and ``from m import f as g``
so that renaming a sink does not hide it.

What it still does not have is data flow. It can see that a SQL string was built
by concatenation and that some call executes a query; it cannot see whether the
value that reached the sink is the one that was tainted, nor whether a check
performed three lines earlier makes the sink safe. That gap is the whole point of
including it: it marks the boundary between "recognises a shape" and "reasons
about a program".
"""

from __future__ import annotations

import ast
from pathlib import Path

from .base import Finding

SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM")
WEAK_DIGESTS = ("md5", "sha1", "md4", "sha")
RANDOM_DRAWS = (
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "getrandbits",
    "seed",
    "Random",
    "sample",
    "shuffle",
    "uniform",
)


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for an expression used in call position."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _static_text(node: ast.AST) -> str:
    """Concatenate every string constant reachable inside an expression."""
    chunks: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            chunks.append(child.value)
    return " ".join(chunks)


def _looks_like_sql(node: ast.AST) -> bool:
    text = _static_text(node).upper()
    return any(keyword in text for keyword in SQL_KEYWORDS)


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        #: local name -> canonical dotted name, from import statements
        self.aliases: dict[str, str] = {}
        self.has_compare_digest = False
        self.splits_on_dot: int = 0

    # -- import tracking ---------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def _canonical(self, node: ast.AST) -> str:
        name = _dotted(node)
        if not name:
            return ""
        head, _, rest = name.partition(".")
        if head in self.aliases:
            resolved = self.aliases[head]
            return f"{resolved}.{rest}" if rest else resolved
        return name

    # -- rules -------------------------------------------------------------

    def _add(self, rule_id: str, cwes: tuple[str, ...], node: ast.AST, msg: str) -> None:
        self.findings.append(Finding(rule_id, cwes, getattr(node, "lineno", 0), msg))

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if _looks_like_sql(node) and any(
            isinstance(part, ast.FormattedValue) for part in node.values
        ):
            self._add("AST-SQL-DYNAMIC", ("CWE-89",), node, "SQL built by an f-string")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, (ast.Add, ast.Mod)) and _looks_like_sql(node):
            self._add(
                "AST-SQL-DYNAMIC", ("CWE-89",), node, "SQL built by concatenation or %"
            )
        if isinstance(node.op, ast.Div):
            left = self._canonical(node.left)
            if left.endswith("Path") or left.endswith("pathlib.Path"):
                self._add(
                    "AST-PATH-BUILD",
                    ("CWE-22",),
                    node,
                    "filesystem path built by joining a Path with another value",
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._canonical(node.func)
        tail = name.rsplit(".", 1)[-1]

        if tail == "format" and _looks_like_sql(node.func):
            self._add("AST-SQL-DYNAMIC", ("CWE-89",), node, "SQL built by str.format")

        if tail == "compare_digest":
            self.has_compare_digest = True

        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                self._add(
                    "AST-CMD-SHELL",
                    ("CWE-78",),
                    node,
                    "subprocess invoked with shell=True",
                )

        if name in ("os.system", "os.popen"):
            self._add(
                "AST-CMD-EXEC", ("CWE-78",), node, f"command executed through {name}"
            )

        if name == "yaml.unsafe_load":
            self._add(
                "AST-DESER-YAML", ("CWE-502",), node, "YAML parsed with unsafe_load"
            )
        elif name == "yaml.load":
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            loader_name = self._canonical(loader) if loader is not None else ""
            if not loader_name.endswith("SafeLoader"):
                self._add(
                    "AST-DESER-YAML",
                    ("CWE-502",),
                    node,
                    "yaml.load without an explicit SafeLoader",
                )

        if name in ("pickle.load", "pickle.loads", "pickle.Unpickler"):
            self._add(
                "AST-DESER-PICKLE", ("CWE-502",), node, f"data decoded through {name}"
            )

        if name in ("open", "io.open") or tail in ("read_text", "read_bytes"):
            argument = node.args[0] if node.args else getattr(node.func, "value", None)
            if argument is not None:
                inner = self._canonical(argument)
                if inner in ("os.path.join", "posixpath.join", "ntpath.join") or (
                    isinstance(argument, ast.BinOp)
                ):
                    self._add(
                        "AST-PATH-OPEN",
                        ("CWE-22",),
                        node,
                        "file opened from a constructed path",
                    )

        if name.startswith("hashlib.") and tail.lower() in WEAK_DIGESTS:
            self._add(
                "AST-HASH-WEAK",
                ("CWE-916", "CWE-327"),
                node,
                f"weak digest {tail} used to derive a stored value",
            )
        if name == "hashlib.new" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and str(first.value).lower() in WEAK_DIGESTS:
                self._add(
                    "AST-HASH-WEAK",
                    ("CWE-916", "CWE-327"),
                    node,
                    f"weak digest {first.value} selected by name",
                )

        if name.startswith("random.") and tail in RANDOM_DRAWS and tail != "SystemRandom":
            self._add(
                "AST-RANDOM-WEAK",
                ("CWE-330",),
                node,
                "value drawn from the deterministic random module",
            )

        if tail in ("partition", "split") and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and first.value == ".":
                self.splits_on_dot += 1

        self.generic_visit(node)


class StructuralOracle:
    """Syntax-tree rules, alias-aware, without data-flow analysis."""

    name = "structural"

    def version(self) -> str:
        return "soda-structural/ast-1"

    def available(self) -> bool:
        return True

    def scan(self, files: list[Path]) -> dict[Path, list[Finding]]:
        results: dict[Path, list[Finding]] = {}
        for path in files:
            source = path.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                results[path] = [
                    Finding("AST-PARSE-ERROR", (), getattr(exc, "lineno", 0) or 0, str(exc))
                ]
                continue

            visitor = _Visitor()
            visitor.visit(tree)

            # Absence rule: a token is taken apart and nothing in the file ever
            # compares a signature. This is as close as a structural checker gets
            # to a weakness whose signature is an omission.
            if visitor.splits_on_dot and not visitor.has_compare_digest:
                visitor.findings.append(
                    Finding(
                        "AST-SIG-NO-COMPARE",
                        ("CWE-347",),
                        0,
                        "token split apart with no constant-time comparison in the file",
                    )
                )

            if visitor.findings:
                results[path] = visitor.findings
        return results
