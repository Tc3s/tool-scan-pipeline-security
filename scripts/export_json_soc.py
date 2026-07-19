#!/usr/bin/env python3
"""Export SOC/customer JSON using schema v1.

The JSON separates scanner evidence, exploit intelligence, verification status,
and risk. By default `vuln_report_soc.json` is customer-safe/redacted.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.calculate_risk_priority import calculate_risk_for_row
    from scripts.schema_utils import (
        clean_text,
        extract_cves,
        extract_cwes,
        first_nonempty,
        has_sensitive_content,
        loads_json_dict,
        loads_json_list,
        normalize_dataframe_schema,
        normalize_verification_status,
        redact_sensitive,
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
        first_nonempty,
        has_sensitive_content,
        loads_json_dict,
        loads_json_list,
        normalize_dataframe_schema,
        normalize_verification_status,
        redact_sensitive,
        redact_sensitive_deep,
        to_bool,
    )


PROJECT_ROOT = rt.project_root()
QUEUE_FILE = rt.output_dir() / "vuln_validation_queue.csv"
REPORTS_DIR = rt.reports_dir()
INTERNAL_REPORT_DIR = REPORTS_DIR / "internal"
CUSTOMER_SAFE_REPORT_DIR = REPORTS_DIR / "customer_safe"
INPUT_EXCEL = INTERNAL_REPORT_DIR / "vuln_attack_report.xlsx"
LEGACY_INPUT_EXCEL = PROJECT_ROOT / "vuln_attack_report.xlsx"
OUTPUT_JSON = CUSTOMER_SAFE_REPORT_DIR / "vuln_report_soc.json"
OUTPUT_INTERNAL_JSON = INTERNAL_REPORT_DIR / "vuln_report_soc.json"


def nullable(value: Any) -> Any:
    text = clean_text(value)
    return text if text else None


def maybe_redact(value: Any, customer_safe: bool) -> Any:
    if not customer_safe:
        return value
    return redact_sensitive(value) if isinstance(value, str) else value


def maybe_redact_deep(value: Any, customer_safe: bool) -> Any:
    return redact_sensitive_deep(value) if customer_safe else value


def numeric(value: Any, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def integer(value: Any, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def utc_timestamp(value: Any) -> Any:
    text = clean_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        parsed = parsed.replace(tzinfo=local_tz)
    parsed = parsed.astimezone(timezone.utc).replace(microsecond=0)
    return parsed.isoformat().replace("+00:00", "Z")


def parse_url(value: Any):
    text = clean_text(value)
    if not text or "://" not in text:
        return None
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.netloc:
        return None
    return parsed


def parse_network_location(value: Any) -> tuple[int | None, str | None]:
    text = clean_text(value).lower()
    if "/" not in text:
        return None, None
    port_text, protocol = text.rsplit("/", 1)
    if not port_text.isdigit():
        return None, None
    if protocol not in {"tcp", "udp"}:
        return None, None
    return int(port_text), protocol


def normalize_target_fields(asset: Any, location: Any, customer_safe: bool) -> dict[str, Any]:
    asset_text = nullable(asset) or "unknown"
    location_text = nullable(location)
    parsed_url = parse_url(location_text) or parse_url(asset_text)
    host = parsed_url.hostname if parsed_url and parsed_url.hostname else asset_text
    if parse_url(host):
        host = parse_url(host).hostname or host
    safe_location = maybe_redact(location_text, customer_safe)
    safe_url = maybe_redact(parsed_url.geturl(), customer_safe) if parsed_url else None
    network_port, network_protocol = parse_network_location(location_text)
    if parsed_url and parsed_url.port:
        network_port = parsed_url.port
    if parsed_url and parsed_url.scheme in {"http", "https"}:
        network_protocol = parsed_url.scheme
    safe_host = maybe_redact(host, customer_safe)
    return {
        "host": safe_host,
        "location": safe_location,
        "full": f"{safe_host} ({safe_location})" if safe_location and safe_location != safe_host else safe_host,
        "url": {
            "full": safe_url,
            "scheme": parsed_url.scheme if parsed_url else None,
            "path": maybe_redact(parsed_url.path, customer_safe) if parsed_url else None,
        },
        "network": {
            "port": network_port,
            "protocol": network_protocol,
        },
    }


def detect_scan_mode(df: pd.DataFrame) -> str:
    verification_statuses = {
        normalize_verification_status(value)
        for value in df.get("verification_status", pd.Series(dtype=str)).dropna().astype(str)
    }
    if verification_statuses - {"NOT_VERIFIED"}:
        return "ACTIVE_VERIFICATION"

    exploit_statuses = {
        clean_text(value).upper()
        for value in df.get("exploit_status", pd.Series(dtype=str)).dropna().astype(str)
    }
    if exploit_statuses:
        return "FAST_EXPLOIT_INTEL"
    return "SCANNER_ONLY"


def soc_context(row) -> str:
    verification_status = normalize_verification_status(row.get("verification_status", "NOT_VERIFIED"))
    priority = clean_text(row.get("priority")).upper()
    if verification_status in {"REPRODUCED", "CONFIRMED_PRESENT"}:
        if priority in {"P1", "P2"}:
            return "CRITICAL_ACTION_REQUIRED"
        if priority == "P3":
            return "VERIFIED_PRIORITY_REVIEW"
        return "VERIFIED_LOW_PRIORITY"
    if verification_status == "FALSE_POSITIVE":
        return "FALSE_POSITIVE_FILTERED"
    if to_bool(row.get("exploit_available", False)):
        return "PUBLIC_EXPLOIT_AVAILABLE"
    return "POTENTIAL_RISK"


def display_input_file(input_file: str, customer_safe: bool) -> str:
    return Path(input_file).name if customer_safe else rt.display_path(input_file)


def exploit_match_basis(exploit_status: Any, sources: list[Any]) -> str:
    status = clean_text(exploit_status).upper()
    source_types = {
        clean_text(source.get("type") if isinstance(source, dict) else source)
        for source in sources
        if clean_text(source.get("type") if isinstance(source, dict) else source)
    }
    if {"Exploit-DB", "Metasploit"} & source_types:
        return "CVE_ONLY_PUBLIC_EXPLOIT_INTEL"
    if "Nuclei" in source_types or status == "EXPLOIT_TEMPLATE_AVAILABLE":
        return "CVE_ONLY_TEMPLATE_INTEL"
    if status == "PUBLIC_EXPLOIT_AVAILABLE":
        return "CVE_ONLY_PUBLIC_EXPLOIT_INTEL"
    if status == "NO_CVE_ID":
        return "NO_CVE"
    if status == "EXPLOIT_INTEL_NOT_RUN":
        return "INTEL_NOT_RUN"
    return "CVE_CHECKED_NO_PUBLIC_SOURCE"


def exploit_match_note(exploit_status: Any, sources: list[Any]) -> str:
    basis = exploit_match_basis(exploit_status, sources)
    if basis.startswith("CVE_ONLY"):
        return "Matched by CVE intelligence source; not proof that this exact service/target is exploitable."
    if basis == "NO_CVE":
        return "No CVE ID was available for exploit-intelligence lookup."
    if basis == "INTEL_NOT_RUN":
        return "Exploit intelligence was not run for this finding."
    return "No public exploit/module/template found in configured local sources."


def annotate_exploit_sources(sources: list[Any], exploit_status: Any, customer_safe: bool) -> list[Any]:
    annotated = []
    for source in sources:
        if not isinstance(source, dict):
            annotated.append(maybe_redact_deep(source, customer_safe))
            continue
        item = dict(source)
        item.setdefault("match_basis", exploit_match_basis(exploit_status, [item]))
        item.setdefault("match_note", exploit_match_note(exploit_status, [item]))
        annotated.append(maybe_redact_deep(item, customer_safe))
    return annotated


def exploit_context_requires_review(sources: list[Any]) -> bool:
    for source in sources:
        if not isinstance(source, dict):
            continue
        context = clean_text(source.get("context_match")).upper()
        if context in {"", "UNKNOWN", "CONTEXT_UNKNOWN", "CONTEXT_NOT_CLASSIFIED", "NOT_CLASSIFIED"}:
            return True
    return False


def exploit_intel_level(match_basis: str, exploit_available: bool) -> str:
    basis = clean_text(match_basis).upper()
    if basis in {"NO_CVE", "INTEL_NOT_RUN"}:
        return "none"
    if basis.startswith("CVE_") or basis == "CVE_CHECKED_NO_PUBLIC_SOURCE":
        return "cve"
    if exploit_available:
        return "cve"
    return "none"


def redaction_would_change(*values: Any) -> bool:
    for value in values:
        if isinstance(value, str) and redact_sensitive(value) != value:
            return True
    return False


def parse_attack_techniques(row) -> list:
    techniques = loads_json_list(row.get("attack_techniques_json"))
    if techniques:
        return techniques
    technique_id = clean_text(row.get("attack_technique_id"))
    if not technique_id:
        return []
    return [{
        "technique_id": technique_id,
        "technique_name": nullable(row.get("attack_technique_name")),
        "tactic": nullable(row.get("attack_tactic")),
        "confidence": numeric(row.get("attack_confidence")),
        "reason": nullable(row.get("reason")),
    }]


def build_finding_identity(row, customer_safe: bool) -> dict:
    location = first_nonempty(row.get("location"), row.get("url_or_port"))
    parts = {
        "scanner": nullable(row.get("scanner")) or "unknown",
        "asset": nullable(row.get("asset")) or "unknown",
        "location": nullable(location) or "",
        "plugin_id": nullable(row.get("plugin_id")) or "",
        "cves": ",".join(extract_cves(row.get("cve"), row.get("cve_list"))),
        "cwes": ",".join(extract_cwes(row.get("cwe"), row.get("cwe_list"))),
        "finding_name": nullable(row.get("finding_name")) or "unknown",
    }
    canonical_key = "|".join(f"{key}={clean_text(value).lower()}" for key, value in parts.items())
    dedup_hash = rt.text_sha256(canonical_key)[:24]
    return {
        "id": f"va-find-{dedup_hash}",
        "dedup_hash": dedup_hash,
        "dedup_key": maybe_redact(canonical_key, customer_safe),
        "dedup_basis": list(parts.keys()),
    }


def build_soc_entry(row, customer_safe: bool) -> dict:
    asset = nullable(row.get("asset")) or "unknown"
    identity = build_finding_identity(row, customer_safe)
    location = nullable(first_nonempty(row.get("location"), row.get("url_or_port")))
    target_fields = normalize_target_fields(asset, location, customer_safe)
    scanner_evidence = first_nonempty(row.get("scanner_evidence"), row.get("evidence"), row.get("description"))
    scanner_solution = first_nonempty(row.get("scanner_solution"), row.get("solution"), row.get("evidence_solution"))
    verification_evidence = clean_text(row.get("verification_evidence"))
    verification_error = clean_text(row.get("verification_error"))
    verification_command = clean_text(row.get("verification_command"))
    exploit_evidence = first_nonempty(row.get("exploit_evidence"), row.get("agent_evidence"))

    sources = loads_json_list(row.get("exploit_sources_json"))
    exploit_status = nullable(row.get("exploit_status")) or nullable(row.get("agent_status")) or "NO_CVE_ID"
    match_basis = nullable(row.get("exploit_match_basis")) or exploit_match_basis(exploit_status, sources)
    match_note = nullable(row.get("exploit_match_note")) or exploit_match_note(exploit_status, sources)
    exploit_available = to_bool(row.get("exploit_available", False))
    context_review_required = bool(to_bool(row.get("exploit_context_review_required", False))) or (
        exploit_available and exploit_context_requires_review(sources)
    )
    context_summary = nullable(row.get("exploit_context_summary"))
    cves = extract_cves(row.get("cve"), row.get("cve_list"))
    cwes = extract_cwes(row.get("cwe"), row.get("cwe_list"))
    verification_status = normalize_verification_status(row.get("verification_status", "NOT_VERIFIED"))
    target_level_proof = verification_status in {"REPRODUCED", "CONFIRMED_PRESENT"}
    redaction_applied = customer_safe and redaction_would_change(
        location,
        row.get("url_or_port"),
        row.get("affected_urls_json"),
        row.get("description"),
        scanner_evidence,
        scanner_solution,
        verification_evidence,
        verification_command,
        verification_error,
        exploit_evidence,
        json.dumps(sources, ensure_ascii=False),
    )
    sensitive_evidence = bool(to_bool(row.get("sensitive_evidence", False))) or has_sensitive_content(
        location,
        row.get("url_or_port"),
        row.get("affected_urls_json"),
        row.get("description"),
        scanner_evidence,
        scanner_solution,
        verification_evidence,
        verification_command,
        verification_error,
        exploit_evidence,
    )
    mapping_low_confidence = (
        bool(to_bool(row.get("needs_review", False)))
        or numeric(row.get("attack_confidence"), 0.0) < 0.7
    )
    attack_tactics = [] if customer_safe and mapping_low_confidence else loads_json_list(row.get("attack_tactics_json"))
    attack_techniques = [] if customer_safe and mapping_low_confidence else parse_attack_techniques(row)

    entry = {
        "schema_version": "1.0",
        "event": {
            "type": "vulnerability_finding",
            "action": "upsert",
            "source": "tool-scan-pipeline-security",
            "dataset": "vulnerability_assessment",
            "observed_at": utc_timestamp(row.get("scan_time")),
            "dedup_hash": identity["dedup_hash"],
        },
        "finding": identity,
        "target": {
            "host": target_fields["host"],
            "asset_type": nullable(row.get("asset_type")),
            "location": target_fields["location"],
            "full": target_fields["full"],
        },
        "url": target_fields["url"],
        "network": target_fields["network"],
        "vulnerability": {
            "name": nullable(row.get("finding_name")),
            "severity": nullable(row.get("severity")),
            "cvss": numeric(row.get("cvss")) if nullable(row.get("cvss")) else None,
            "cves": cves,
            "cwes": cwes,
            "description": maybe_redact(nullable(row.get("description")), customer_safe),
        },
        "scanner": {
            "name": nullable(row.get("scanner")),
            "evidence": maybe_redact(nullable(scanner_evidence), customer_safe),
            "solution": maybe_redact(nullable(scanner_solution), customer_safe),
            "raw_reference": nullable(row.get("raw_reference")),
            "plugin_id": nullable(row.get("plugin_id")),
            "instance_count": integer(row.get("instance_count"), 1),
            "affected_urls": maybe_redact_deep(loads_json_list(row.get("affected_urls_json")), customer_safe),
        },
        "exploit_intel": {
            "status": exploit_status,
            "available": exploit_available,
            "intel_level": exploit_intel_level(match_basis, exploit_available),
            "matched_cves": extract_cves(row.get("exploit_source_cves")),
            "evidence": maybe_redact(nullable(exploit_evidence), customer_safe),
            "sources": annotate_exploit_sources(sources, exploit_status, customer_safe),
            "match_basis": match_basis,
            "match_note": match_note,
            "context_review_required": context_review_required,
            "context_summary": context_summary,
            "epss": {
                "max_score": numeric(row.get("epss_score")),
                "percentile": numeric(row.get("epss_percentile")),
                "source_cve": nullable(row.get("epss_source_cve")),
                "all": loads_json_list(row.get("epss_all_json")),
            },
        },
        "verification": {
            "status": verification_status,
            "target_level_proof": target_level_proof,
            "evidence": maybe_redact(nullable(verification_evidence), customer_safe),
            "method": nullable(row.get("verification_method")),
            "command": maybe_redact(nullable(verification_command), customer_safe),
            "error": maybe_redact(nullable(verification_error), customer_safe),
            "confidence": nullable(row.get("verification_confidence")),
            "started_at": utc_timestamp(row.get("verification_started_at")),
            "completed_at": utc_timestamp(row.get("verification_completed_at")),
            "safe_mode": bool(to_bool(row.get("verification_safe_mode", True))),
            "note": "Public exploit availability is not proof of successful exploitation on this target.",
        },
        "risk": {
            "priority": nullable(row.get("priority")),
            "score": numeric(row.get("risk_score")),
            "reason": nullable(row.get("risk_reason")),
            "components": loads_json_dict(row.get("risk_components_json")),
        },
        "mitre_attack": {
            "tactics": attack_tactics,
            "techniques": attack_techniques,
            "needs_review": bool(to_bool(row.get("needs_review", False))),
        },
        "reporting": {
            "soc_context": soc_context(row),
            "customer_safe": customer_safe,
            "sensitive_evidence": sensitive_evidence,
            "redaction_applied": redaction_applied,
        },
    }
    return entry


def build_summary(df: pd.DataFrame, scan_mode: str) -> dict:
    def counts(column: str) -> dict:
        if column not in df.columns:
            return {}
        return {
            str(key): int(value)
            for key, value in df[column].fillna("UNKNOWN").value_counts().sort_index().items()
        }

    return {
        "total_findings": int(len(df)),
        "scan_mode": scan_mode,
        "by_scanner": counts("scanner"),
        "by_severity": counts("severity"),
        "by_priority": counts("priority"),
        "by_exploit_status": counts("exploit_status"),
        "by_verification_status": counts("verification_status"),
        "public_exploit_available": int(df["exploit_available"].apply(to_bool).sum())
        if "exploit_available" in df.columns
        else 0,
        "exploit_context_review_required": int(df["exploit_context_review_required"].apply(to_bool).sum())
        if "exploit_context_review_required" in df.columns
        else 0,
        "needs_attack_mapping_review": int(df["needs_review"].apply(to_bool).sum())
        if "needs_review" in df.columns
        else 0,
        "sensitive_evidence_rows": int(df["sensitive_evidence"].apply(to_bool).sum())
        if "sensitive_evidence" in df.columns
        else 0,
    }


def refresh_risk_columns(df: pd.DataFrame) -> pd.DataFrame:
    refreshed = df.copy()
    risk_rows = [calculate_risk_for_row(row) for _, row in refreshed.iterrows()]
    refreshed["risk_score"] = [item["risk_score"] for item in risk_rows]
    refreshed["priority"] = [item["priority"] for item in risk_rows]
    refreshed["risk_reason"] = [item["risk_reason"] for item in risk_rows]
    refreshed["risk_components_json"] = [item["risk_components_json"] for item in risk_rows]
    return refreshed


def load_input_dataframe() -> tuple[pd.DataFrame, str]:
    if QUEUE_FILE.exists():
        return normalize_dataframe_schema(pd.read_csv(QUEUE_FILE)), str(QUEUE_FILE)
    if INPUT_EXCEL.exists():
        return normalize_dataframe_schema(pd.read_excel(INPUT_EXCEL)), str(INPUT_EXCEL)
    if LEGACY_INPUT_EXCEL.exists():
        return normalize_dataframe_schema(pd.read_excel(LEGACY_INPUT_EXCEL)), str(LEGACY_INPUT_EXCEL)
    raise FileNotFoundError(f"Missing input: {QUEUE_FILE} or {INPUT_EXCEL}")


def build_report(df: pd.DataFrame, input_file: str, customer_safe: bool) -> dict:
    scan_mode = detect_scan_mode(df)
    run_meta = rt.base_run_metadata(
        input_file=input_file,
        verifier_file=rt.verifier_file(),
    )
    run_meta["generated_at"] = utc_timestamp(run_meta.get("generated_at"))
    if customer_safe:
        run_meta["project_root"] = None
        run_meta["run_dir"] = Path(run_meta["run_dir"]).name if run_meta.get("run_dir") else None
        run_meta["input_file"] = Path(input_file).name
        run_meta["verifier_file"] = Path(run_meta["verifier_file"]).name if run_meta.get("verifier_file") else None
        run_meta["verifier_sha256"] = None
        run_meta["tool_versions"] = {}
    return {
        "schema_version": "1.0",
        "run_metadata": {
            **run_meta,
            "input_file": display_input_file(input_file, customer_safe),
            "report_mode": "customer_safe" if customer_safe else "internal_full",
        },
        "provenance": {
            "pipeline": "tool-scan-pipeline-security",
            "pipeline_version": os.environ.get("VA_PIPELINE_VERSION") or "local",
            "exporter": {
                "path": rt.display_path(Path(__file__), customer_safe=customer_safe),
                "sha256": rt.file_sha256(Path(__file__)),
            },
            "source_input_sha256": rt.file_sha256(input_file),
            "raw_sources": [
                {
                    "kind": "zap_json",
                    "path": rt.display_path(rt.raw_dir() / "zap_report.json", customer_safe=customer_safe),
                    "sha256": rt.file_sha256(rt.raw_dir() / "zap_report.json"),
                },
                {
                    "kind": "openvas_xml",
                    "path": rt.display_path(rt.raw_dir() / "openvas_report.xml", customer_safe=customer_safe),
                    "sha256": rt.file_sha256(rt.raw_dir() / "openvas_report.xml"),
                },
            ],
        },
        "reporting": {
            "customer_safe": customer_safe,
            "redaction_scope": "secret-bearing URL/query values, credentials, tokens, scanner evidence, solutions, exploit evidence, and exploit source strings"
            if customer_safe
            else "none",
            "schema_name": "va_soc_report",
            "ingest_contract": {
                "event_type": "vulnerability_finding",
                "event_action": "upsert",
                "dedup_field": "finding.dedup_hash",
                "event_time_field": "event.observed_at",
                "target_proof_field": "verification.status",
                "confirmed_target_statuses": ["REPRODUCED", "CONFIRMED_PRESENT"],
                "public_exploit_available_is_target_proof": False,
                "recommended_alert_field": "reporting.soc_context",
            },
        },
        "summary": build_summary(df, scan_mode),
        "warnings": [
            "Exploit intelligence means a public module/PoC/template exists; it is not proof that the target was exploited.",
            "Verification status must be REPRODUCED or CONFIRMED_PRESENT before claiming target-level exploitability.",
            "Exploit source matching is CVE-based and may need product/service context review.",
        ],
        "findings": [
            build_soc_entry(row, customer_safe=customer_safe)
            for _, row in df.iterrows()
            if clean_text(row.get("finding_name"))
        ],
    }


def write_json(path: Path, report: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)


def parse_to_soc_json():
    print("📊 [SOC] Exporting SOC JSON schema v1...")
    try:
        df, input_file = load_input_dataframe()
        df = refresh_risk_columns(df)
    except Exception as exc:
        print(f"❌ Cannot load input data: {exc}")
        return

    customer_report = build_report(df, input_file, customer_safe=True)
    internal_report = build_report(df, input_file, customer_safe=False)

    write_json(OUTPUT_JSON, customer_report)
    write_json(OUTPUT_INTERNAL_JSON, internal_report)

    print(f"✅ [SOC] Customer-safe JSON: {OUTPUT_JSON} ({len(customer_report['findings'])} findings)")
    print(f"✅ [SOC] Internal JSON: {OUTPUT_INTERNAL_JSON} ({len(internal_report['findings'])} findings)")


if __name__ == "__main__":
    parse_to_soc_json()
