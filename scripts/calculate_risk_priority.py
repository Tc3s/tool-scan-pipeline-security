#!/usr/bin/env python3
"""Risk scoring engine for VA triage.

This module deliberately separates scanner severity, exploit intelligence, and
active verification. A public exploit/module is not the same as reproduced
exploitation on the target.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import (
        clean_text,
        extract_cves,
        first_nonempty,
        has_sensitive_content,
        legacy_status_to_exploit_status,
        normalize_dataframe_schema,
        normalize_verification_status,
        to_bool,
    )
except ImportError:
    import runtime_context as rt
    from schema_utils import (
        clean_text,
        extract_cves,
        first_nonempty,
        has_sensitive_content,
        legacy_status_to_exploit_status,
        normalize_dataframe_schema,
        normalize_verification_status,
        to_bool,
    )


PROJECT_ROOT = rt.project_root()
DATA_DIR = rt.run_dir()

INPUT_FILE = rt.output_dir() / "vuln_attack_mapped.csv"
OUTPUT_FILE = rt.output_dir() / "vuln_attack_enriched.csv"

SEVERITY_BASE = {
    "Critical": 80,
    "High": 60,
    "Medium": 35,
    "Low": 15,
    "Informational": 0,
    "Info": 0,
    "Log": 0,
    "Unknown": 0,
}


def normalize_severity(val: Any) -> str:
    if pd.isna(val):
        return "Unknown"
    value = str(val).strip().title()
    if value in {"Crit", "Sever"}:
        return "Critical"
    if value in {"Mod", "Moderate"}:
        return "Medium"
    if value in {"Information", "Informational"}:
        return "Informational"
    return value or "Unknown"


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _exploit_component(exploit_status: str, exploit_sources_json: Any, exploit_available: bool) -> tuple[int, str]:
    sources = []
    if not pd.isna(exploit_sources_json):
        try:
            loaded = json.loads(str(exploit_sources_json))
            if isinstance(loaded, list):
                sources = loaded
        except json.JSONDecodeError:
            sources = []

    source_types = {str(source.get("type", "")) for source in sources if isinstance(source, dict)}

    if {"Metasploit", "Exploit-DB"} & source_types:
        return 15, "public exploit module/PoC available"
    if "Nuclei" in source_types:
        return 8, "public detection/exploit template available"
    if exploit_status == "PUBLIC_EXPLOIT_AVAILABLE":
        return 12, "public exploit available"
    if exploit_status == "EXPLOIT_TEMPLATE_AVAILABLE":
        return 8, "public template available"
    if exploit_available:
        return 8, "exploit availability flag present"
    return 0, "no public exploit found"


def _epss_component(epss_score: float) -> tuple[int, str]:
    if epss_score >= 0.95:
        return 15, "EPSS >= 0.95"
    if epss_score >= 0.70:
        return 10, "EPSS >= 0.70"
    if epss_score >= 0.30:
        return 5, "EPSS >= 0.30"
    if epss_score > 0:
        return 2, "EPSS > 0"
    return 0, "no EPSS signal"


def _verification_component(verification_status: str) -> tuple[int, str]:
    if verification_status == "REPRODUCED":
        return 20, "actively reproduced on target"
    if verification_status == "CONFIRMED_PRESENT":
        return 15, "confirmed present on target"
    if verification_status == "CHECKED_NOT_REPRODUCED":
        return -10, "checked but not reproduced"
    if verification_status == "FALSE_POSITIVE":
        return -50, "classified false positive"
    return 0, "not actively verified"


def _exposure_component(location: Any, asset_type: Any) -> tuple[int, str]:
    location_text = clean_text(location)
    asset_type_text = clean_text(asset_type).lower()
    if location_text.startswith(("http://", "https://")) or asset_type_text == "web":
        return 5, "web-exposed finding"
    if "/tcp" in location_text or "/udp" in location_text:
        return 5, "network service exposed"
    return 0, "exposure not classified"


def _strong_scanner_proof(row) -> bool:
    return has_sensitive_content(
        row.get("finding_name"),
        row.get("description"),
        row.get("scanner_evidence"),
        row.get("evidence"),
    ) or any(
        term in clean_text(first_nonempty(row.get("finding_name"), row.get("description"), row.get("scanner_evidence"))).lower()
        for term in [
            "passwordless",
            "default credential",
            "default/hardcoded credential",
            "backdoor",
            "root access",
            "remote code execution",
            " rce ",
        ]
    )


def priority_from_score(score: float) -> str:
    if score >= 90:
        return "P1"
    if score >= 70:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def calculate_risk_for_row(row) -> dict[str, Any]:
    severity = normalize_severity(row.get("severity", "Unknown"))
    base_score = SEVERITY_BASE.get(severity, 0)

    epss_score = _safe_float(first_nonempty(row.get("epss_score"), row.get("epss_max")), 0.0)
    epss_points, epss_reason = _epss_component(epss_score)

    exploit_status = legacy_status_to_exploit_status(row.get("exploit_status", row.get("agent_status", "")))
    exploit_available = to_bool(row.get("exploit_available", False)) or exploit_status in {
        "PUBLIC_EXPLOIT_AVAILABLE",
        "EXPLOIT_TEMPLATE_AVAILABLE",
    }
    exploit_points, exploit_reason = _exploit_component(
        exploit_status,
        row.get("exploit_sources_json", "[]"),
        exploit_available,
    )

    verification_status = normalize_verification_status(row.get("verification_status", "NOT_VERIFIED"))
    verification_points, verification_reason = _verification_component(verification_status)

    exposure_points, exposure_reason = _exposure_component(
        first_nonempty(row.get("location"), row.get("url_or_port")),
        row.get("asset_type"),
    )

    strong_proof = _strong_scanner_proof(row)
    strong_proof_points = 10 if strong_proof and severity in {"Critical", "High"} else 0

    raw_score = base_score + epss_points + exploit_points + verification_points + exposure_points + strong_proof_points
    final_score = max(0, min(100, raw_score))

    # Guardrails: public exploit availability alone should not make Low/Medium findings P1.
    if verification_status not in {"REPRODUCED", "CONFIRMED_PRESENT"}:
        if severity == "Low":
            final_score = min(final_score, 69)
        elif severity == "Medium":
            if exploit_available and epss_score >= 0.90:
                final_score = max(final_score, 70)
            final_score = min(final_score, 89)

    if severity == "Critical" and (exploit_available or strong_proof):
        final_score = max(final_score, 90)

    priority = priority_from_score(final_score)

    components = {
        "severity": severity,
        "severity_base": base_score,
        "epss_score": epss_score,
        "epss_points": epss_points,
        "exploit_status": exploit_status,
        "exploit_points": exploit_points,
        "verification_status": verification_status,
        "verification_points": verification_points,
        "exposure_points": exposure_points,
        "strong_scanner_proof": strong_proof,
        "strong_scanner_proof_points": strong_proof_points,
        "raw_score_before_guardrails": raw_score,
    }

    reason_parts = [
        f"{severity} scanner severity ({base_score})",
        epss_reason,
        exploit_reason,
        verification_reason,
        exposure_reason,
    ]
    if strong_proof_points:
        reason_parts.append("scanner evidence indicates credentials/backdoor/root/RCE condition")
    cves = extract_cves(row.get("cve"), row.get("cve_list"))
    epss_source = clean_text(row.get("epss_source_cve"))
    if epss_source:
        reason_parts.append(f"EPSS source CVE: {epss_source}")
    elif cves:
        reason_parts.append(f"CVEs considered: {', '.join(cves[:5])}")

    return {
        "risk_score": round(float(final_score), 1),
        "priority": priority,
        "risk_reason": "; ".join(reason_parts),
        "risk_components_json": json.dumps(components, ensure_ascii=False),
    }


def calculate_risk_priority(severity: str, epss_score: float = 0.0, is_weaponized: bool = False) -> tuple:
    """Backward-compatible wrapper used by older callers."""
    detail = calculate_risk_for_row({
        "severity": severity,
        "epss_score": epss_score,
        "exploit_available": is_weaponized,
        "exploit_status": "PUBLIC_EXPLOIT_AVAILABLE" if is_weaponized else "NO_PUBLIC_EXPLOIT_FOUND",
        "verification_status": "NOT_VERIFIED",
    })
    return detail["risk_score"], detail["priority"]


def get_risk_score(severity):
    legacy_weights = {
        "Critical": 10,
        "High": 8,
        "Medium": 5,
        "Low": 2,
        "Informational": 0,
        "Info": 0,
        "Log": 0,
        "Unknown": 0,
    }
    return legacy_weights.get(normalize_severity(severity), 0)


def assign_priority(score):
    if score >= 9:
        return "P1"
    if score >= 7:
        return "P1"
    if score >= 5:
        return "P2"
    if score >= 1:
        return "P3"
    return "P4"


def calculate_risk():
    print("\n🚀 [RISK] Calculating triage priority (schema v1)...")

    if not os.path.exists(INPUT_FILE):
        print(f"❌ LỖI: Không tìm thấy file đầu vào: {INPUT_FILE}")
        sys.exit(1)

    try:
        df = normalize_dataframe_schema(pd.read_csv(INPUT_FILE))
        print(f"   -> Loaded {len(df)} findings.")
    except Exception as e:
        print(f"❌ LỖI: Không đọc được file CSV. Chi tiết: {e}")
        sys.exit(1)

    risk_rows = [calculate_risk_for_row(row) for _, row in df.iterrows()]
    df["risk_score"] = [item["risk_score"] for item in risk_rows]
    df["priority"] = [item["priority"] for item in risk_rows]
    df["risk_reason"] = [item["risk_reason"] for item in risk_rows]
    df["risk_components_json"] = [item["risk_components_json"] for item in risk_rows]

    df["_sort_p"] = df["priority"].str.extract(r"(\d+)").astype(int)
    df.sort_values(by=["_sort_p", "risk_score"], ascending=[True, False], inplace=True)
    df.drop(columns=["_sort_p"], inplace=True)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    priority_cols = ["priority", "risk_score", "risk_reason", "severity", "finding_name", "scanner"]
    ordered = [c for c in priority_cols if c in df.columns] + [c for c in df.columns if c not in priority_cols]
    df = df[ordered]
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"✅ [RISK] Saved: {OUTPUT_FILE}")
    print("📊 Priority distribution:")
    print(df["priority"].value_counts().sort_index().to_string())


if __name__ == "__main__":
    calculate_risk()
