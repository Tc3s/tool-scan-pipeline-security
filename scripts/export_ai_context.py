#!/usr/bin/env python3
"""Export compact JSONL context for AI verification agents.

The CSV files remain the source of truth for the pipeline. These JSONL files
are optimized for agent consumption: one finding per line, no mostly-empty
columns, parsed lists instead of CSV-escaped JSON strings, and grouped ZAP
instances for web findings.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.calculate_risk_priority import calculate_risk_for_row
    from scripts.schema_utils import (
        clean_text,
        extract_cves,
        extract_cwes,
        loads_json_list,
        redact_sensitive_deep,
        to_bool,
    )
except ImportError:
    import runtime_context as rt
    from calculate_risk_priority import calculate_risk_for_row
    from schema_utils import (
        clean_text,
        extract_cves,
        extract_cwes,
        loads_json_list,
        redact_sensitive_deep,
        to_bool,
    )


PROJECT_ROOT = rt.project_root()
DATA_DIR = rt.run_dir()
QUEUE_FILE = rt.output_dir() / "vuln_validation_queue.csv"
ENRICHED_FILE = rt.output_dir() / "vuln_attack_enriched.csv"
ZAP_INSTANCES_FILE = rt.normalized_dir() / "zap_instances.csv"
AI_CONTEXT_DIR = rt.ai_context_dir()

MAX_TEXT = {
    "description": 900,
    "scanner_evidence": 900,
    "scanner_solution": 650,
    "risk_reason": 450,
    "exploit_evidence": 700,
    "verification_evidence": 700,
}
MAX_AFFECTED_URLS = 12
MAX_ZAP_INSTANCES_PER_FINDING = 8
MAX_EXPLOIT_SOURCES = 8
LEGACY_AGENT_STATUSES = {
    "NO_CVE_ID",
    "NO_PUBLIC_EXPLOIT_FOUND",
    "PUBLIC_EXPLOIT_AVAILABLE",
    "EXPLOIT_TEMPLATE_AVAILABLE",
    "INTEL_CHECK_ERROR",
}


def is_empty(value: Any) -> bool:
    if value is None:
        return True
    try:
        if pd.isna(value):
            return True
    except (TypeError, ValueError):
        pass
    if isinstance(value, str):
        return value.strip() == "" or value.strip().lower() in {"nan", "none", "null"}
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return False


def clip(value: Any, limit: int) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[: limit - 15].rstrip() + "...[truncated]"


def maybe_float(value: Any) -> float | None:
    if is_empty(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def maybe_int(value: Any) -> int | None:
    number = maybe_float(value)
    if number is None:
        return None
    return int(number)


def put(target: dict[str, Any], key: str, value: Any):
    if not is_empty(value):
        target[key] = value


def short_id(row: pd.Series, ordinal: int) -> str:
    material = "|".join(
        clean_text(row.get(column))
        for column in ["scanner", "asset", "location", "finding_name", "plugin_id"]
    )
    digest = hashlib.sha1(material.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"F{ordinal:04d}-{digest}"


def load_queue() -> tuple[pd.DataFrame, Path]:
    if QUEUE_FILE.exists():
        return pd.read_csv(QUEUE_FILE), QUEUE_FILE
    if ENRICHED_FILE.exists():
        return pd.read_csv(ENRICHED_FILE), ENRICHED_FILE
    raise FileNotFoundError(f"Missing {QUEUE_FILE} and {ENRICHED_FILE}")


def zap_group_key(row: pd.Series | dict[str, Any]) -> tuple[str, str, str]:
    return (
        clean_text(row.get("asset")),
        clean_text(row.get("finding_name")),
        clean_text(row.get("plugin_id")),
    )


def load_zap_instances() -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    if not ZAP_INSTANCES_FILE.exists():
        return {}

    df = pd.read_csv(ZAP_INSTANCES_FILE)
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for _, row in df.iterrows():
        item = {
            "method": clean_text(row.get("method")) or "GET",
            "url": clean_text(row.get("location")),
            "param": clean_text(row.get("param")),
            "evidence": clip(row.get("scanner_evidence"), 240),
        }
        item = {key: value for key, value in item.items() if not is_empty(value)}
        grouped.setdefault(zap_group_key(row), []).append(item)
    return grouped


def load_zap_instance_records() -> list[dict[str, Any]]:
    if not ZAP_INSTANCES_FILE.exists():
        return []

    df = pd.read_csv(ZAP_INSTANCES_FILE)
    records = []
    for _, row in df.iterrows():
        record = {
            "finding_name": clean_text(row.get("finding_name")),
            "severity": clean_text(row.get("severity")),
            "plugin_id": clean_text(row.get("plugin_id")),
            "asset": clean_text(row.get("asset")),
            "method": clean_text(row.get("method")) or "GET",
            "url": clean_text(row.get("location")),
            "param": clean_text(row.get("param")),
            "evidence": clip(row.get("scanner_evidence"), 260),
            "cwes": extract_cwes(row.get("cwe"), row.get("cwe_list")),
            "instance_index": maybe_int(row.get("instance_index")),
        }
        records.append(prune_empty(record))
    return records


def compact_exploit_sources(row: pd.Series) -> list[dict[str, Any]]:
    sources = []
    for source in loads_json_list(row.get("exploit_sources_json")):
        if not isinstance(source, dict):
            continue
        item = {
            "type": clean_text(source.get("type")),
            "cve": clean_text(source.get("cve")),
            "module": clean_text(source.get("module")),
            "template": clean_text(source.get("template")),
            "title": clean_text(source.get("title")),
            "match_basis": clean_text(source.get("match_basis")),
            "context_match": clean_text(source.get("context_match")),
        }
        sources.append({key: value for key, value in item.items() if not is_empty(value)})
        if len(sources) >= MAX_EXPLOIT_SOURCES:
            break
    return sources


def build_record(row: pd.Series, ordinal: int, zap_groups: dict[tuple[str, str, str], list[dict[str, Any]]]) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": short_id(row, ordinal),
        "priority": clean_text(row.get("priority")),
        "risk_score": maybe_float(row.get("risk_score")),
        "severity": clean_text(row.get("severity")),
        "scanner": clean_text(row.get("scanner")),
        "target": {
            "asset": clean_text(row.get("asset")),
            "type": clean_text(row.get("asset_type")),
            "location": clean_text(row.get("location")),
        },
        "vulnerability": {
            "name": clean_text(row.get("finding_name")),
            "plugin_id": clean_text(row.get("plugin_id")),
            "raw_reference": clean_text(row.get("raw_reference")),
            "cvss": maybe_float(row.get("cvss")),
            "cves": extract_cves(row.get("cve"), row.get("cve_list")),
            "cwes": extract_cwes(row.get("cwe"), row.get("cwe_list")),
        },
        "verification": {
            "status": clean_text(row.get("verification_status")) or "NOT_VERIFIED",
        },
    }

    for source, key, limit in [
        ("description", "description", MAX_TEXT["description"]),
        ("scanner_evidence", "scanner_evidence", MAX_TEXT["scanner_evidence"]),
        ("scanner_solution", "scanner_solution", MAX_TEXT["scanner_solution"]),
    ]:
        put(record["vulnerability"], key, clip(row.get(source), limit))

    affected_urls = loads_json_list(row.get("affected_urls_json"))[:MAX_AFFECTED_URLS]
    if affected_urls:
        record["target"]["affected_urls"] = affected_urls

    risk = {}
    put(risk, "reason", clip(row.get("risk_reason"), MAX_TEXT["risk_reason"]))
    put(risk, "needs_attack_mapping_review", to_bool(row.get("needs_review")))
    put(risk, "sensitive_evidence", to_bool(row.get("sensitive_evidence")))
    if risk:
        record["risk"] = risk

    attack = {}
    put(attack, "tactic", clean_text(row.get("attack_tactic")))
    put(attack, "technique_id", clean_text(row.get("attack_technique_id")))
    put(attack, "technique_name", clean_text(row.get("attack_technique_name")))
    put(attack, "confidence", maybe_float(row.get("attack_confidence")))
    put(attack, "mapping_method", clean_text(row.get("mapping_method")))
    if attack:
        record["attack"] = attack

    exploit = {
        "status": clean_text(row.get("exploit_status")) or "NO_CVE_ID",
        "available": to_bool(row.get("exploit_available")),
    }
    put(exploit, "matched_cves", extract_cves(row.get("exploit_source_cves")))
    put(exploit, "match_basis", clean_text(row.get("exploit_match_basis")))
    put(exploit, "match_note", clean_text(row.get("exploit_match_note")))
    put(exploit, "context_review_required", to_bool(row.get("exploit_context_review_required")))
    put(exploit, "context_summary", clean_text(row.get("exploit_context_summary")))
    put(exploit, "evidence", clip(row.get("exploit_evidence"), MAX_TEXT["exploit_evidence"]))
    sources = compact_exploit_sources(row)
    if sources:
        exploit["sources"] = sources
    record["exploit_intel"] = exploit

    put(record["verification"], "evidence", clip(row.get("verification_evidence"), MAX_TEXT["verification_evidence"]))
    put(record["verification"], "method", clean_text(row.get("verification_method")))
    put(record["verification"], "command", clean_text(row.get("verification_command")))
    put(record["verification"], "error", clip(row.get("verification_error"), 400))
    put(record["verification"], "confidence", clean_text(row.get("verification_confidence")))
    put(record["verification"], "started_at", clean_text(row.get("verification_started_at")))
    put(record["verification"], "completed_at", clean_text(row.get("verification_completed_at")))
    if "verification_safe_mode" in row.index:
        record["verification"]["safe_mode"] = to_bool(row.get("verification_safe_mode"))
    if clean_text(row.get("scanner")) == "ZAP":
        instances = zap_groups.get(zap_group_key(row), [])
        if instances:
            record["zap_instances"] = instances[:MAX_ZAP_INSTANCES_PER_FINDING]
            if len(instances) > MAX_ZAP_INSTANCES_PER_FINDING:
                record["zap_instances_omitted"] = len(instances) - MAX_ZAP_INSTANCES_PER_FINDING

    return prune_empty(record)


def prune_empty(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: prune_empty(item)
            for key, item in value.items()
            if not is_empty(prune_empty(item))
        }
    if isinstance(value, list):
        return [prune_empty(item) for item in value if not is_empty(prune_empty(item))]
    return value


def write_jsonl(path: Path, records: list[dict[str, Any]], customer_safe: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            item = redact_sensitive_deep(record) if customer_safe else record
            handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")


def write_manifest(path: Path, records: list[dict[str, Any]], queue_source: Path, customer_safe: bool):
    run_meta = rt.base_run_metadata(
        input_file=queue_source,
        verifier_file=rt.verifier_file(),
    )
    if customer_safe:
        run_meta["project_root"] = None
        run_meta["run_dir"] = Path(run_meta["run_dir"]).name if run_meta.get("run_dir") else None
        run_meta["input_file"] = queue_source.name
        run_meta["verifier_file"] = Path(run_meta["verifier_file"]).name if run_meta.get("verifier_file") else None
        run_meta["verifier_sha256"] = None
        run_meta["tool_versions"] = {}
    summary = {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "run_metadata": run_meta,
        "customer_safe": customer_safe,
        "source_files": {
            "queue": rt.display_path(queue_source, customer_safe=customer_safe),
            "zap_instances": rt.display_path(ZAP_INSTANCES_FILE, customer_safe=customer_safe) if ZAP_INSTANCES_FILE.exists() else None,
        },
        "record_count": len(records),
        "zap_instances_compact_count": len(load_zap_instance_records()) if ZAP_INSTANCES_FILE.exists() else 0,
        "priority_counts": {},
        "scanner_counts": {},
        "intended_use": [
            "AI verifier context; CSV remains pipeline source of truth.",
            "One JSONL line equals one finding.",
            "Use zap_instances for ZAP findings before constructing web requests.",
            "Do not treat exploit_intel as target-level verification.",
        ],
    }
    for key in ["priority", "scanner"]:
        counts: dict[str, int] = {}
        for record in records:
            value = clean_text(record.get(key)) or "UNKNOWN"
            counts[value] = counts.get(value, 0) + 1
        summary[f"{key}_counts"] = dict(sorted(counts.items()))

    if customer_safe:
        summary = redact_sensitive_deep(summary)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def export_ai_context():
    df, queue_source = load_queue()
    risk_rows = [calculate_risk_for_row(row) for _, row in df.iterrows()]
    df["risk_score"] = [item["risk_score"] for item in risk_rows]
    df["priority"] = [item["priority"] for item in risk_rows]
    df["risk_reason"] = [item["risk_reason"] for item in risk_rows]
    df["risk_components_json"] = [item["risk_components_json"] for item in risk_rows]
    zap_groups = load_zap_instances()
    zap_instance_records = load_zap_instance_records()

    records = [
        build_record(row, ordinal, zap_groups)
        for ordinal, (_, row) in enumerate(df.iterrows(), start=1)
        if clean_text(row.get("finding_name"))
    ]

    outputs = []
    for mode, customer_safe in [("internal", False), ("customer_safe", True)]:
        out_dir = AI_CONTEXT_DIR / mode
        context_path = out_dir / "verification_context.jsonl"
        zap_context_path = out_dir / "zap_instances_compact.jsonl"
        manifest_path = out_dir / "manifest.json"
        write_jsonl(context_path, records, customer_safe=customer_safe)
        write_jsonl(zap_context_path, zap_instance_records, customer_safe=customer_safe)
        write_manifest(manifest_path, records, queue_source, customer_safe=customer_safe)
        outputs.extend([context_path, zap_context_path, manifest_path])

    print("✅ [AI_CONTEXT] Exported compact AI verification context:")
    for path in outputs:
        print(f"   -> {path}")


if __name__ == "__main__":
    export_ai_context()
