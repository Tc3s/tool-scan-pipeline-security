#!/usr/bin/env python3
"""Static policy checks for AI-generated verifier code.

This is not a sandbox. It is a fast fail gate that catches patterns that are
not acceptable for production-safe verification before a verifier is compiled
or executed.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

try:
    from scripts.runtime_context import file_sha256, utc_now
except ImportError:
    from runtime_context import file_sha256, utc_now


FORBIDDEN_TEXT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("metadata endpoint", re.compile(r"169\.254\.169\.254")),
    ("localhost pivot literal", re.compile(r"(?i)\b(localhost|127\.0\.0\.1|::1)\b")),
    ("file URI", re.compile(r"(?i)\bfile://")),
    ("data URI", re.compile(r"(?i)\bdata:")),
    ("system file probe", re.compile(r"(?i)(/etc/passwd|/proc/self|/proc/)")),
    ("sqlmap high risk", re.compile(r"(?i)--risk\s+[2-9]")),
    ("sqlmap high level", re.compile(r"(?i)--level\s+[2-9]")),
    ("sqlmap dumping", re.compile(r"(?i)(--dump|--dump-all|--os-shell|--file-read|--file-write|--crawl|--forms)")),
    ("dangerous nmap script category", re.compile(r"(?i)--script[=\s][^\n]*(intrusive|vuln|exploit|dos|brute)")),
    ("nmap range scan", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\s*-\s*(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")),
    ("brute force wording", re.compile(r"(?i)(brute\s*force|password\s*spray|credential\s*stuffing)")),
    ("state changing method", re.compile(r"(?i)\b(DELETE|PUT|PATCH)\b")),
    ("dangerous upload/write action", re.compile(r"(?i)\b(upload|delete|create account|write file|drop table)\b")),
    ("direct queue mutation", re.compile(r"(?i)vuln_validation_queue\.csv")),
    ("dataframe csv write", re.compile(r"(?i)\.to_csv\s*\(")),
]


FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
}

REQUIRED_CONTRACT_STRINGS = {
    "--dry-run",
    "--mode",
    "--context-file",
    "--zap-context-file",
    "--scope-file",
    "--plan-file",
    "--results-file",
    "--approval-file",
}


@dataclass
class Finding:
    severity: str
    rule: str
    detail: str
    line: int | None = None


def _attr_name(node: ast.AST) -> tuple[str | None, str | None]:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    if isinstance(node, ast.Name):
        return None, node.id
    return None, None


class PolicyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.import_aliases: dict[str, str] = {}

    def _canonical_name(self, module: str | None, name: str | None) -> tuple[str | None, str | None]:
        if module in self.import_aliases:
            module = self.import_aliases[module]
        if module is None and name in self.import_aliases:
            canonical = self.import_aliases[name]
            if "." in canonical:
                parts = canonical.rsplit(".", 1)
                return parts[0], parts[1]
            return None, canonical
        return module, name

    def _literal_args(self, node: ast.Call) -> list[str]:
        values: list[str] = []
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                values.append(str(arg.value))
            elif isinstance(arg, (ast.List, ast.Tuple)):
                for item in arg.elts:
                    if isinstance(item, ast.Constant):
                        values.append(str(item.value))
        return values

    def visit_Call(self, node: ast.Call) -> Any:
        module, name = _attr_name(node.func)
        module, name = self._canonical_name(module, name)
        if (module, name) in FORBIDDEN_CALLS:
            self.findings.append(Finding("high", "forbidden_call", f"{module}.{name}", node.lineno))
        if module == "subprocess" and name in {"run", "Popen"}:
            has_timeout = any(keyword.arg == "timeout" for keyword in node.keywords)
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.findings.append(Finding("critical", "shell_true", "subprocess shell=True", node.lineno))
            if name == "run" and not has_timeout:
                self.findings.append(Finding("high", "subprocess_timeout_missing", "subprocess.run without timeout", node.lineno))
            literal_args = " ".join(self._literal_args(node)).lower()
            if "sqlmap" in literal_args and "va_allow_sqlmap" not in literal_args:
                self.findings.append(Finding("high", "sqlmap_without_env_gate", "sqlmap command without VA_ALLOW_SQLMAP gate", node.lineno))
        if module == "requests" and name in {"get", "post", "head", "options", "request"}:
            if not any(keyword.arg == "timeout" for keyword in node.keywords):
                self.findings.append(Finding("high", "requests_timeout_missing", f"requests.{name} without timeout", node.lineno))
            if name == "post":
                self.findings.append(Finding("medium", "post_requires_review", "POST request requires explicit scope review", node.lineno))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            self.import_aliases[local_name] = alias.name
            if alias.name in {"pexpect", "paramiko"}:
                self.findings.append(Finding("medium", "manual_review_import", alias.name, node.lineno))
            if alias.name in {"socket", "aiohttp"}:
                self.findings.append(Finding("medium", "network_import_requires_review", alias.name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        for alias in node.names:
            local_name = alias.asname or alias.name
            if node.module:
                self.import_aliases[local_name] = f"{node.module}.{alias.name}"
        if node.module in {"pexpect", "paramiko"}:
            self.findings.append(Finding("medium", "manual_review_import", node.module, node.lineno))
        if node.module in {"socket", "aiohttp"}:
            self.findings.append(Finding("medium", "network_import_requires_review", node.module, node.lineno))
        self.generic_visit(node)


def validate_source(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    findings: list[Finding] = []

    for label, pattern in FORBIDDEN_TEXT_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            context_start = max(0, line - 10)
            context_end = min(len(lines), line + 3)
            line_text = "\n".join(lines[context_start:context_end]).lower()
            if any(term in line_text for term in [
                "forbidden",
                "reject",
                "deny",
                "block",
                "not allowed",
                "credential",
                "file_read",
                "write_action",
                "scanner_active_proof",
                "skipped_result",
                "manual_result",
                "host_is_forbidden",
            ]):
                continue
            findings.append(Finding("high", "forbidden_text", label, line))

    for required in sorted(REQUIRED_CONTRACT_STRINGS):
        if required not in text:
            findings.append(Finding("high", "missing_contract_option", required, None))

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        findings.append(Finding("critical", "syntax_error", str(exc), exc.lineno))
    else:
        visitor = PolicyVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)

    high_or_critical = [item for item in findings if item.severity in {"high", "critical"}]
    return {
        "schema_version": "1.0",
        "validated_at": utc_now(),
        "file": str(path),
        "sha256": file_sha256(path),
        "passed": not high_or_critical,
        "findings": [asdict(item) for item in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate AI-generated verifier code against production safety policy.")
    parser.add_argument("path", help="Python file to validate")
    parser.add_argument("--json", action="store_true", help="Print JSON result")
    args = parser.parse_args(argv)

    result = validate_source(args.path)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"[POLICY] {status} {result['file']}")
        for finding in result["findings"]:
            line = f":{finding['line']}" if finding.get("line") else ""
            print(f"  - {finding['severity']} {finding['rule']}{line}: {finding['detail']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
