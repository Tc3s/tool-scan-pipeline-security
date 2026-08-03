#!/usr/bin/env python3
"""Stable contract for per-run AI-generated verification scripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import (
        VERIFICATION_STATUSES,
        clean_text,
        normalize_verification_status,
        redact_sensitive,
        to_bool,
    )
except ImportError:
    import runtime_context as rt
    from schema_utils import (
        VERIFICATION_STATUSES,
        clean_text,
        normalize_verification_status,
        redact_sensitive,
        to_bool,
    )


import ipaddress
import socket

APPROVAL_SCHEMA_VERSION = "1.0"
PLAN_SCHEMA_VERSION = "generated-verifier-plan-1.0"
RESULT_SCHEMA_VERSION = "verification-result-1.0"

CONFIRMED_STATUSES = {"REPRODUCED", "CONFIRMED_PRESENT"}
NEGATIVE_STATUSES = {"CHECKED_NOT_REPRODUCED", "FALSE_POSITIVE"}
MANUAL_STATUSES = {"NEEDS_MANUAL_REVIEW", "SKIPPED_SAFE_MODE", "ERROR"}
APPLICABLE_RESULT_STATUSES = CONFIRMED_STATUSES | NEGATIVE_STATUSES | MANUAL_STATUSES

CONFIDENCE_VALUES = {"LOW", "MEDIUM", "HIGH"}

VERIFICATION_UPDATE_COLUMNS = [
    "verification_status",
    "verification_evidence",
    "verification_method",
    "verification_command",
    "verification_error",
    "verification_confidence",
    "verification_started_at",
    "verification_completed_at",
    "verification_safe_mode",
    "verification_run_id",
    "verification_result_id",
]

PROMPT_MODE_BLACKBOX = "BLACKBOX_UNAUTHENTICATED"
PROMPT_MODE_GREYBOX = "GREYBOX_AUTHENTICATED"


class ContractError(ValueError):
    """Raised when a verifier, manifest, scope, or result violates contract."""


def load_json(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ContractError(f"JSON document must be an object: {path}")
    return payload


def write_json(path: str | Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def is_private_or_loopback_ip(host_or_ip: str) -> bool:
    clean_host = clean_text(host_or_ip).lower().rstrip(".")
    if clean_host in {"localhost", "127.0.0.1", "::1", "169.254.169.254", "metadata.google.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(clean_host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        pass
    return False


def canonical_target(target: str) -> str:
    value = clean_text(target)
    if not value:
        raise ContractError("Target is empty.")
    if "://" not in value:
        value = f"http://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ContractError(f"Unsupported target scheme: {parsed.scheme or '<empty>'}")
    if not parsed.hostname:
        raise ContractError(f"Target hostname is missing: {target}")
    host = parsed.hostname.lower().rstrip(".")
    if is_private_or_loopback_ip(host):
        raise ContractError(f"Refusing unsafe target host or private IP: {host}")
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{parsed.scheme}://{netloc}"


def target_parts(target: str) -> dict[str, Any]:
    canonical = canonical_target(target)
    parsed = urlparse(canonical)
    return {
        "input": clean_text(target),
        "canonical": canonical,
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "sha256": rt.text_sha256(canonical),
    }


def finding_id(row: Any, ordinal: int) -> str:
    material = "|".join(
        clean_text(row.get(column))
        for column in ["scanner", "asset", "location", "finding_name", "plugin_id"]
    )
    digest = hashlib.sha1(material.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"F{ordinal:04d}-{digest}"


def count_jsonl_records(path: str | Path) -> int:
    path = Path(path)
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def context_files() -> dict[str, Path]:
    base = rt.ai_context_dir() / "internal"
    return {
        "manifest": base / "manifest.json",
        "verification_context": base / "verification_context.jsonl",
        "zap_instances": base / "zap_instances_compact.jsonl",
    }


def context_hashes() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, path in context_files().items():
        result[name] = {
            "path": rt.display_path(path),
            "sha256": rt.file_sha256(path),
            "record_count": count_jsonl_records(path) if path.suffix == ".jsonl" else None,
        }
    return result


def validate_scope(target: str, scope_file: str | Path | None = None) -> list[str]:
    path = Path(scope_file) if scope_file else rt.scope_file()
    if not path.exists():
        return [f"Missing scope file: {rt.display_path(path)}"]
    scope = rt.load_yaml_file(path)
    parts = target_parts(target)
    errors: list[str] = []

    allowed_hosts = [clean_text(item).lower().rstrip(".") for item in scope.get("allowed_hosts", [])]
    if not allowed_hosts:
        errors.append("scope.allowed_hosts must be explicit before dry-run approval/live verification.")
    elif parts["host"] not in allowed_hosts:
        errors.append(f"target host {parts['host']} is not in scope.allowed_hosts.")

    allowed_schemes = [clean_text(item).lower() for item in scope.get("allowed_schemes", [])]
    if allowed_schemes and parts["scheme"] not in allowed_schemes:
        errors.append(f"target scheme {parts['scheme']} is not in scope.allowed_schemes.")

    raw_ports = scope.get("allowed_ports", [])
    allowed_ports = {int(port) for port in raw_ports if clean_text(port)}
    if allowed_ports and int(parts["port"]) not in allowed_ports:
        errors.append(f"target port {parts['port']} is not in scope.allowed_ports.")

    methods = {clean_text(method).upper() for method in scope.get("allowed_methods", [])}
    unsafe_methods = methods & {"POST", "PUT", "PATCH", "DELETE"}
    if unsafe_methods and not to_bool(scope.get("state_changing_methods_approved", False)):
        errors.append(f"scope.allowed_methods includes non-default methods without explicit approval: {sorted(unsafe_methods)}")

    return errors


def build_approval_manifest(
    *,
    target: str,
    mode: str,
    verifier_file: str | Path,
    queue_file: str | Path,
    plan_file: str | Path,
    policy_result: dict[str, Any],
) -> dict[str, Any]:
    verifier_path = Path(verifier_file)
    queue_path = Path(queue_file)
    plan_path = Path(plan_file)
    scope_path = rt.scope_file()
    plan_payload = load_json(plan_path) if plan_path.exists() else {}

    return {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "created_at": rt.utc_now(),
        "approved": False,
        "approved_by": None,
        "approved_at": None,
        "mode": mode,
        "target": target_parts(target),
        "scope": {
            "path": rt.display_path(scope_path),
            "sha256": rt.file_sha256(scope_path),
            "validation_errors": validate_scope(target, scope_path),
        },
        "verifier": {
            "path": rt.display_path(verifier_path),
            "sha256": rt.file_sha256(verifier_path),
        },
        "queue": {
            "path": rt.display_path(queue_path),
            "sha256": rt.file_sha256(queue_path),
            "record_count": count_csv_records(queue_path),
        },
        "ai_context": context_hashes(),
        "plan": {
            "path": rt.display_path(plan_path),
            "sha256": rt.file_sha256(plan_path),
            "schema_version": plan_payload.get("schema_version"),
            "planned_total": plan_payload.get("planned_total", plan_payload.get("total_findings")),
            "planned_status_counts": plan_payload.get("planned_status_counts", {}),
            "planned_methods": plan_payload.get("planned_methods", []),
        },
        "policy": policy_result,
    }


def count_csv_records(path: str | Path) -> int:
    path = Path(path)
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", errors="ignore") as handle:
        line_count = sum(1 for _ in handle)
    return max(0, line_count - 1)


def assert_manifest_ready_for_approval(manifest: dict[str, Any]) -> None:
    errors = []
    if manifest.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        errors.append("approval manifest schema_version mismatch.")
    if manifest.get("approved"):
        errors.append("approval manifest is already approved.")
    if manifest.get("scope", {}).get("validation_errors"):
        errors.extend(manifest["scope"]["validation_errors"])
    if not manifest.get("verifier", {}).get("sha256"):
        errors.append("verifier sha256 is missing.")
    if not manifest.get("queue", {}).get("sha256"):
        errors.append("queue sha256 is missing.")
    if not manifest.get("plan", {}).get("sha256"):
        errors.append("dry-run plan sha256 is missing.")
    if manifest.get("policy", {}).get("passed") is not True:
        errors.append("policy validation did not pass.")
    if errors:
        raise ContractError("; ".join(errors))


def approve_manifest(path: str | Path, *, operator: str, target: str, verifier_file: str | Path, queue_file: str | Path) -> dict[str, Any]:
    manifest = load_json(path)
    assert_manifest_ready_for_approval(manifest)
    current_errors = manifest_mismatch_errors(
        manifest,
        target=target,
        verifier_file=verifier_file,
        queue_file=queue_file,
    )
    if current_errors:
        raise ContractError("; ".join(current_errors))
    manifest["approved"] = True
    manifest["approved_by"] = clean_text(operator) or "operator"
    manifest["approved_at"] = rt.utc_now()
    write_json(path, manifest)
    return manifest


def manifest_mismatch_errors(
    manifest: dict[str, Any],
    *,
    target: str,
    verifier_file: str | Path,
    queue_file: str | Path,
) -> list[str]:
    expected_target = target_parts(target)["canonical"]
    expected_verifier_hash = rt.file_sha256(verifier_file)
    expected_queue_hash = rt.file_sha256(queue_file)
    expected_scope_hash = rt.scope_hash()
    errors: list[str] = []

    if manifest.get("target", {}).get("canonical") != expected_target:
        errors.append("target in approval manifest does not match current target.")
    if manifest.get("verifier", {}).get("sha256") != expected_verifier_hash:
        errors.append("verifier hash changed after dry-run approval manifest was created.")
    if manifest.get("queue", {}).get("sha256") != expected_queue_hash:
        errors.append("queue hash changed after dry-run approval manifest was created.")
    if manifest.get("scope", {}).get("sha256") != expected_scope_hash:
        errors.append("scope hash changed after dry-run approval manifest was created.")

    for name, meta in context_hashes().items():
        saved_hash = manifest.get("ai_context", {}).get(name, {}).get("sha256")
        if saved_hash != meta.get("sha256"):
            errors.append(f"AI context hash changed after dry-run: {name}.")
    return errors


def assert_approved_manifest(
    path: str | Path,
    *,
    target: str,
    verifier_file: str | Path,
    queue_file: str | Path,
) -> dict[str, Any]:
    manifest = load_json(path)
    if manifest.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        raise ContractError("approval manifest schema_version mismatch.")
    if manifest.get("approved") is not True:
        raise ContractError("approval manifest is not approved.")
    if not manifest.get("approved_by") or not manifest.get("approved_at"):
        raise ContractError("approval manifest is missing approved_by/approved_at.")
    errors = manifest_mismatch_errors(
        manifest,
        target=target,
        verifier_file=verifier_file,
        queue_file=queue_file,
    )
    if errors:
        raise ContractError("; ".join(errors))
    return manifest


def normalize_result_status(status: Any) -> str:
    normalized = normalize_verification_status(status)
    if normalized not in APPLICABLE_RESULT_STATUSES:
        raise ContractError(f"Unsupported verification result status: {status}")
    return normalized


def validate_result_record(record: dict[str, Any], allowed_finding_ids: set[str]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ContractError("Each verification result must be a JSON object.")

    finding_id_value = clean_text(record.get("finding_id") or record.get("id"))
    if not finding_id_value:
        raise ContractError("Verification result is missing finding_id.")
    if finding_id_value not in allowed_finding_ids:
        raise ContractError(f"Unknown finding_id in verification result: {finding_id_value}")

    status = normalize_result_status(record.get("status") or record.get("verification_status"))
    evidence = clean_text(record.get("evidence") or record.get("evidence_summary"), max_length=800)
    method = clean_text(record.get("method"), max_length=160)
    command = clean_text(record.get("command") or record.get("command_summary"), max_length=400)
    error = clean_text(record.get("error"), max_length=400)
    confidence = clean_text(record.get("confidence")).upper()
    if confidence and confidence not in CONFIDENCE_VALUES:
        raise ContractError(f"Invalid confidence for {finding_id_value}: {confidence}")

    if status in CONFIRMED_STATUSES and (not evidence or not method):
        raise ContractError(f"{status} result for {finding_id_value} requires evidence and method.")
    if status in CONFIRMED_STATUSES and confidence == "LOW":
        raise ContractError(f"{status} result for {finding_id_value} cannot use LOW confidence.")
    if status in NEGATIVE_STATUSES and not evidence:
        raise ContractError(f"{status} result for {finding_id_value} requires evidence.")
    if status in MANUAL_STATUSES and not (evidence or error):
        raise ContractError(f"{status} result for {finding_id_value} requires evidence or error.")

    safe_mode = to_bool(record.get("safe_mode", record.get("verification_safe_mode", True)))
    if not safe_mode and status != "ERROR":
        raise ContractError(f"Non-error result for {finding_id_value} must keep safe_mode=true.")

    return {
        "finding_id": finding_id_value,
        "status": status,
        "evidence": redact_sensitive(evidence),
        "method": redact_sensitive(method),
        "command": redact_sensitive(command),
        "error": redact_sensitive(error),
        "confidence": confidence,
        "started_at": clean_text(record.get("started_at") or record.get("verification_started_at")),
        "completed_at": clean_text(record.get("completed_at") or record.get("checked_at") or record.get("verification_completed_at")),
        "safe_mode": safe_mode,
    }
