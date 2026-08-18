#!/usr/bin/env python3
"""Runtime path, scope, and audit helpers for the VA pipeline.

Defaults remain backward-compatible with the existing ``data/`` layout. Set
``VA_RUN_DIR`` to route all runtime artifacts to a separate run directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def project_root() -> Path:
    env_root = os.environ.get("VA_PROJECT_ROOT")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


_SESSION_RUN_DIR: Path | None = None


def run_dir() -> Path:
    global _SESSION_RUN_DIR
    env_run_dir = os.environ.get("VA_RUN_DIR")
    if env_run_dir:
        return Path(env_run_dir).expanduser().resolve()
    run_id = os.environ.get("VA_RUN_ID")
    if run_id:
        return project_root() / "runs" / safe_run_id(run_id)
    if os.environ.get("VA_USE_STATIC_DATA_DIR") == "true":
        return project_root() / "data"
    if _SESSION_RUN_DIR is None:
        auto_run_name = f"run_{datetime.now().astimezone().strftime('%Y%m%d_%H%M%S')}"
        _SESSION_RUN_DIR = project_root() / "runs" / auto_run_name
    return _SESSION_RUN_DIR


def safe_run_id(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value.strip())
    return cleaned.strip(".-") or datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def raw_dir() -> Path:
    return run_dir() / "raw"


def normalized_dir() -> Path:
    return run_dir() / "normalized"


def output_dir() -> Path:
    return run_dir() / "output"


def reports_dir() -> Path:
    return run_dir() / "reports"


def ai_context_dir() -> Path:
    return run_dir() / "ai_context"


def generated_dir() -> Path:
    return run_dir() / "generated"


def verifier_file() -> Path:
    env_verifier = os.environ.get("VA_VERIFIER_FILE")
    if env_verifier:
        return Path(env_verifier).expanduser().resolve()
    return generated_dir() / "verify_vulns.py"


def verification_dir() -> Path:
    return run_dir() / "verification"


def verification_plan_file() -> Path:
    env_plan = os.environ.get("VA_VERIFICATION_PLAN_FILE")
    if env_plan:
        return Path(env_plan).expanduser().resolve()
    return verification_dir() / "verification_plan.json"


def verification_results_file() -> Path:
    env_results = os.environ.get("VA_VERIFICATION_RESULTS_FILE")
    if env_results:
        return Path(env_results).expanduser().resolve()
    return verification_dir() / "verification_results.jsonl"


def logs_dir() -> Path:
    return run_dir() / "logs"


def scope_file() -> Path:
    env_scope = os.environ.get("VA_SCOPE_FILE")
    if env_scope:
        return Path(env_scope).expanduser().resolve()
    return run_dir() / "scope.yml"


def approval_file() -> Path:
    env_approval = os.environ.get("VA_APPROVAL_FILE")
    if env_approval:
        return Path(env_approval).expanduser().resolve()
    return run_dir() / "approval_manifest.json"


def ensure_runtime_dirs() -> None:
    for path in [
        raw_dir(),
        normalized_dir(),
        output_dir(),
        reports_dir() / "internal",
        reports_dir() / "customer_safe",
        ai_context_dir() / "internal",
        ai_context_dir() / "customer_safe",
        generated_dir(),
        verification_dir(),
        logs_dir(),
    ]:
        path.mkdir(parents=True, exist_ok=True)


def display_path(path: str | Path, *, customer_safe: bool = False) -> str:
    path = Path(path)
    if customer_safe:
        return path.name
    try:
        return str(path.resolve().relative_to(project_root()))
    except ValueError:
        return str(path)


def file_sha256(path: str | Path) -> str | None:
    path = Path(path)
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data if isinstance(data, dict) else {}


def write_json_file(path: str | Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def tool_version(command: str) -> str | None:
    binary = shutil.which(command)
    if not binary:
        return None
    probes = {
        "python": ["--version"],
        "python3": ["--version"],
        "nuclei": ["-version"],
        "nmap": ["--version"],
        "sqlmap": ["--version"],
        "docker": ["--version"],
        "searchsploit": ["-h"],
    }
    args = [binary] + probes.get(command, ["--version"])
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.SubprocessError):
        return binary
    output = (result.stdout or result.stderr or "").strip().splitlines()
    return output[0] if output else binary


def collect_tool_versions(commands: list[str] | None = None) -> dict[str, str | None]:
    commands = commands or ["python3", "docker", "nmap", "sqlmap", "nuclei", "searchsploit"]
    return {command: tool_version(command) for command in commands}


def scope_hash(path: str | Path | None = None) -> str | None:
    target = Path(path) if path else scope_file()
    return file_sha256(target)


def base_run_metadata(*, input_file: str | Path | None = None, verifier_file: str | Path | None = None) -> dict[str, Any]:
    return {
        "run_id": os.environ.get("VA_RUN_ID") or run_dir().name,
        "generated_at": utc_now(),
        "project_root": display_path(project_root()),
        "run_dir": display_path(run_dir()),
        "input_file": display_path(input_file) if input_file else None,
        "input_sha256": file_sha256(input_file) if input_file else None,
        "scope_file": display_path(scope_file()) if scope_file().exists() else None,
        "scope_sha256": scope_hash(),
        "verifier_file": display_path(verifier_file) if verifier_file else None,
        "verifier_sha256": file_sha256(verifier_file) if verifier_file else None,
        "tool_versions": collect_tool_versions(),
    }


def write_scope_template(path: str | Path, target: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Lay config/scope.example.yml lam mau goc master
    example_scope = project_root() / "config" / "scope.example.yml"
    if example_scope.exists():
        payload = load_yaml_file(example_scope)
    else:
        payload = {}

    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = (parsed.hostname or "").lower().rstrip(".")
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port

    payload["schema_version"] = payload.get("schema_version", "1.0")
    payload["target"] = target
    
    allowed_hosts = [str(h).lower().rstrip(".") for h in payload.get("allowed_hosts", [])]
    if host and host not in allowed_hosts and host != "target.example":
        allowed_hosts.append(host)
    payload["allowed_hosts"] = [h for h in allowed_hosts if h != "target.example"] or ([host] if host else [])

    allowed_ports = payload.get("allowed_ports", [])
    if port and port not in allowed_ports:
        allowed_ports.append(port)
    payload["allowed_ports"] = allowed_ports

    allowed_schemes = [str(s).lower() for s in payload.get("allowed_schemes", [])]
    if parsed.scheme and parsed.scheme not in allowed_schemes:
        allowed_schemes.append(parsed.scheme)
    payload["allowed_schemes"] = list(dict.fromkeys(["http", "https"] + allowed_schemes))
    payload.setdefault("allowed_methods", ["GET", "HEAD", "OPTIONS", "POST"])
    payload["state_changing_methods_approved"] = True
    payload["allow_zap_full_scan"] = True
    payload.setdefault("allow_unscoped_scan", False)
    payload.setdefault("same_origin_redirects_only", True)
    payload.setdefault("max_requests_per_second", 1)
    payload.setdefault("max_concurrency", 1)
    payload.setdefault("auth_allowed", False)
    payload["notes"] = [
        "Scope automatically populated from config/scope.example.yml template.",
        "Adjust allowed_hosts / allowed_ports if additional targets are in scope.",
    ]

    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False)
