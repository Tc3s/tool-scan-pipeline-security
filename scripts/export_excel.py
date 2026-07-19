#!/usr/bin/env python3
"""Export internal and customer-safe Excel reports."""

from __future__ import annotations

import json
import os
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
        first_nonempty,
        has_sensitive_content,
        loads_json_list,
        normalize_dataframe_schema,
        normalize_verification_status,
        priority_sort_key,
        redact_sensitive,
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
        loads_json_list,
        normalize_dataframe_schema,
        normalize_verification_status,
        priority_sort_key,
        redact_sensitive,
        to_bool,
    )


PROJECT_ROOT = rt.project_root()
DATA_DIR = rt.run_dir()
OUTPUT_DIR = rt.output_dir()
REPORTS_DIR = rt.reports_dir()
INTERNAL_REPORT_DIR = REPORTS_DIR / "internal"
CUSTOMER_SAFE_REPORT_DIR = REPORTS_DIR / "customer_safe"

INPUT_FILE = OUTPUT_DIR / "vuln_attack_enriched.csv"
QUEUE_FILE = OUTPUT_DIR / "vuln_validation_queue.csv"
ZAP_INSTANCES_FILE = rt.normalized_dir() / "zap_instances.csv"

OUTPUT_FILE = INTERNAL_REPORT_DIR / "vuln_attack_report.xlsx"
CUSTOMER_OUTPUT_FILE = CUSTOMER_SAFE_REPORT_DIR / "vuln_attack_report.xlsx"

CUSTOMER_REDACTION_COLUMNS = [
    "location",
    "url_or_port",
    "affected_urls_json",
    "description",
    "scanner_evidence",
    "scanner_solution",
    "evidence",
    "solution",
    "verification_evidence",
    "exploit_evidence",
    "agent_evidence",
    "exploit_sources_json",
]

CUSTOMER_DROP_COLUMNS = [
    "agent_status",
    "agent_command",
    "agent_evidence",
    "verification_command",
    "risk_components_json",
    "raw_reference",
    "epss_all_json",
    "exploit_sources_json",
]

CONFIRMED_STATUSES = {"REPRODUCED", "CONFIRMED_PRESENT"}
REVIEW_STATUSES = {"NOT_VERIFIED", "NEEDS_MANUAL_REVIEW", "SKIPPED_SAFE_MODE", "ERROR"}
FALSE_POSITIVE_STATUSES = {"FALSE_POSITIVE", "CHECKED_NOT_REPRODUCED"}


def load_findings() -> tuple[pd.DataFrame, str]:
    if QUEUE_FILE.exists():
        df = pd.read_csv(QUEUE_FILE)
        source = str(QUEUE_FILE)
    elif INPUT_FILE.exists():
        df = pd.read_csv(INPUT_FILE)
        source = str(INPUT_FILE)
    else:
        raise FileNotFoundError("No enriched/validation CSV found.")
    return normalize_dataframe_schema(df), source


def sort_findings(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["_priority_sort"] = df["priority"].apply(priority_sort_key) if "priority" in df.columns else 99
    score_col = "risk_score" if "risk_score" in df.columns else "cvss"
    df[score_col] = pd.to_numeric(df.get(score_col, 0), errors="coerce").fillna(0)
    df.sort_values(by=["_priority_sort", score_col], ascending=[True, False], inplace=True)
    df.drop(columns=["_priority_sort"], inplace=True)
    return df


def refresh_risk_columns(df: pd.DataFrame) -> pd.DataFrame:
    refreshed = df.copy()
    risk_rows = [calculate_risk_for_row(row) for _, row in refreshed.iterrows()]
    refreshed["risk_score"] = [item["risk_score"] for item in risk_rows]
    refreshed["priority"] = [item["priority"] for item in risk_rows]
    refreshed["risk_reason"] = [item["risk_reason"] for item in risk_rows]
    refreshed["risk_components_json"] = [item["risk_components_json"] for item in risk_rows]
    return refreshed


def redact_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    redacted = df.copy()
    changed = pd.Series(False, index=redacted.index)

    for column in CUSTOMER_REDACTION_COLUMNS:
        if column in redacted.columns:
            before = redacted[column].fillna("").astype(str)
            redacted[column] = redacted[column].apply(lambda value: redact_sensitive(value) if isinstance(value, str) else value)
            after = redacted[column].fillna("").astype(str)
            changed = changed | before.ne(after)

    detected_sensitive = df.apply(
        lambda row: has_sensitive_content(*(row.get(column) for column in CUSTOMER_REDACTION_COLUMNS)),
        axis=1,
    )
    existing_sensitive = (
        redacted["sensitive_evidence"].apply(to_bool)
        if "sensitive_evidence" in redacted.columns
        else pd.Series(False, index=redacted.index)
    )
    redacted["sensitive_evidence"] = existing_sensitive | detected_sensitive | changed
    redacted["redaction_applied"] = changed
    return redacted


def display_source(source: str, customer_safe: bool) -> str:
    return Path(source).name if customer_safe else source


def build_summary(df: pd.DataFrame, source: str, customer_safe: bool) -> pd.DataFrame:
    run_meta = rt.base_run_metadata(
        input_file=source,
        verifier_file=rt.verifier_file(),
    )
    rows = [
        ("Run", "run_id", run_meta.get("run_id"), "Unique runtime identifier."),
        ("Run", "input_file", display_source(source, customer_safe), "Source used to build this report."),
        ("Run", "input_sha256", run_meta.get("input_sha256"), "Input integrity hash."),
        ("Run", "scope_sha256", run_meta.get("scope_sha256"), "Assessment scope integrity hash."),
        ("Run", "verifier_sha256", run_meta.get("verifier_sha256") if not customer_safe else None, "Internal verifier hash."),
        ("Findings", "total_findings", len(df), "Total rows in the report."),
        (
            "Findings",
            "verified_target_level",
            int(df["verification_status"].apply(lambda value: normalize_verification_status(value) in CONFIRMED_STATUSES).sum())
            if "verification_status" in df
            else 0,
            "Rows with REPRODUCED or CONFIRMED_PRESENT.",
        ),
        (
            "Findings",
            "requires_manual_review",
            int(df["verification_status"].apply(lambda value: normalize_verification_status(value) in REVIEW_STATUSES).sum())
            if "verification_status" in df
            else 0,
            "Rows not safely proven by automation.",
        ),
        ("Threat Intel", "public_exploit_available", int(df["exploit_available"].apply(to_bool).sum()) if "exploit_available" in df else 0, "CVE-level public exploit/template signal, not target proof."),
        ("Review", "needs_attack_mapping_review", int(df["needs_review"].apply(to_bool).sum()) if "needs_review" in df else 0, "ATT&CK mappings that should be reviewed."),
        (
            "Review",
            "exploit_context_review_required",
            int(df["exploit_context_review_required"].apply(to_bool).sum())
            if "exploit_context_review_required" in df
            else 0,
            "Exploit-intel matches needing product/version context review.",
        ),
        ("Review", "sensitive_evidence_rows", int(df["sensitive_evidence"].apply(to_bool).sum()) if "sensitive_evidence" in df else 0, "Rows where sensitive evidence was detected/redacted."),
        (
            "Semantics",
            "exploit_intel_scope",
            "CVE-level public exploit/template intelligence only; product/service context still requires analyst review.",
            "Do not create confirmed-exploit incidents from exploit-intel alone.",
        ),
        (
            "Semantics",
            "verification_scope",
            "Only REPRODUCED or CONFIRMED_PRESENT means target-level exploitability was verified.",
            "Use verification fields for confirmed target-level claims.",
        ),
    ]
    for column in ["scanner", "severity", "priority", "exploit_status", "verification_status"]:
        if column in df.columns:
            for key, count in df[column].fillna("UNKNOWN").value_counts().sort_index().items():
                rows.append(("Counts", f"{column}:{key}", int(count), "Distribution count."))
    return pd.DataFrame(rows, columns=["section", "metric", "value", "note"])


def human_verification_status(status: Any) -> str:
    normalized = normalize_verification_status(status)
    labels = {
        "REPRODUCED": "Đã tái hiện an toàn trên target",
        "CONFIRMED_PRESENT": "Đã xác nhận tồn tại",
        "CHECKED_NOT_REPRODUCED": "Đã kiểm tra nhưng không tái hiện",
        "FALSE_POSITIVE": "Dương tính giả",
        "NEEDS_MANUAL_REVIEW": "Cần rà soát thủ công",
        "SKIPPED_SAFE_MODE": "Bỏ qua vì giới hạn an toàn",
        "ERROR": "Lỗi khi kiểm chứng",
        "NOT_VERIFIED": "Chưa kiểm chứng",
    }
    return labels.get(normalized, normalized)


def triage_state(row: pd.Series) -> str:
    status = normalize_verification_status(row.get("verification_status", "NOT_VERIFIED"))
    priority = clean_text(row.get("priority")).upper()
    if status in CONFIRMED_STATUSES:
        if priority in {"P1", "P2"}:
            return "Confirmed high-priority action"
        if priority == "P3":
            return "Confirmed, plan remediation"
        return "Confirmed low-priority hardening"
    if status == "FALSE_POSITIVE":
        return "Filtered false positive"
    if status == "CHECKED_NOT_REPRODUCED":
        return "Checked but not reproduced"
    if status == "SKIPPED_SAFE_MODE":
        return "Manual review required for safety"
    if status == "NEEDS_MANUAL_REVIEW":
        return "Manual review required"
    if status == "ERROR":
        return "Verification error"
    if to_bool(row.get("exploit_available", False)):
        return "Potential risk with public exploit intelligence"
    return "Potential risk"


def exploit_summary(row: pd.Series) -> str:
    status = clean_text(row.get("exploit_status")) or "EXPLOIT_INTEL_NOT_RUN"
    if to_bool(row.get("exploit_available", False)):
        cves = ", ".join(extract_cves(row.get("exploit_source_cves"))) or "matching CVE"
        return f"Có nguồn public liên quan tới {cves} ({status}); đây chưa phải bằng chứng target khai thác được"
    if status == "NO_CVE_ID":
        return "Không có CVE ID"
    if status == "EXPLOIT_INTEL_NOT_RUN":
        return "Chưa chạy exploit intelligence"
    if status == "NO_PUBLIC_EXPLOIT_FOUND":
        return "Chưa thấy exploit public trong nguồn đã cấu hình"
    return status


def evidence_summary(row: pd.Series, max_length: int = 450) -> str:
    return first_nonempty(
        row.get("verification_evidence"),
        row.get("scanner_evidence"),
        row.get("description"),
        max_length=max_length,
    )


def remediation_summary(row: pd.Series, max_length: int = 450) -> str:
    return first_nonempty(
        row.get("scanner_solution"),
        row.get("solution"),
        row.get("risk_reason"),
        max_length=max_length,
    )


def build_action_plan(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in sort_findings(df).iterrows():
        rows.append({
            "priority": row.get("priority"),
            "risk_score": row.get("risk_score"),
            "triage_state": triage_state(row),
            "verification": human_verification_status(row.get("verification_status")),
            "finding": row.get("finding_name"),
            "asset": row.get("asset"),
            "location": first_nonempty(row.get("location"), row.get("url_or_port"), max_length=160),
            "severity": row.get("severity"),
            "confidence": row.get("verification_confidence"),
            "public_exploit_intel": exploit_summary(row),
            "evidence_summary": evidence_summary(row),
            "recommended_action": remediation_summary(row),
            "cves": ", ".join(extract_cves(row.get("cve"), row.get("cve_list"))),
            "cwes": ", ".join(extract_cwes(row.get("cwe"), row.get("cwe_list"))),
            "scanner": row.get("scanner"),
            "plugin_id": row.get("plugin_id"),
        })
    return pd.DataFrame(rows)


def build_status_view(df: pd.DataFrame, statuses: set[str]) -> pd.DataFrame:
    mask = df["verification_status"].apply(lambda value: normalize_verification_status(value) in statuses)
    return build_action_plan(df[mask].copy())


def build_scanner_evidence_view(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in sort_findings(df).iterrows():
        rows.append({
            "priority": row.get("priority"),
            "finding": row.get("finding_name"),
            "asset": row.get("asset"),
            "location": first_nonempty(row.get("location"), row.get("url_or_port"), max_length=180),
            "scanner": row.get("scanner"),
            "plugin_id": row.get("plugin_id"),
            "scanner_evidence": first_nonempty(row.get("scanner_evidence"), row.get("evidence"), max_length=650),
            "verification_evidence": clean_text(row.get("verification_evidence"), max_length=650),
            "solution": remediation_summary(row, max_length=650),
        })
    return pd.DataFrame(rows)


def build_mapping_review(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in sort_findings(df).iterrows():
        if not to_bool(row.get("needs_review", False)) and pd.to_numeric(pd.Series([row.get("attack_confidence")]), errors="coerce").fillna(0).iloc[0] >= 0.7:
            continue
        rows.append({
            "finding": row.get("finding_name"),
            "asset": row.get("asset"),
            "priority": row.get("priority"),
            "candidate_tactic": row.get("attack_tactic"),
            "candidate_technique": row.get("attack_technique_id"),
            "candidate_technique_name": row.get("attack_technique_name"),
            "confidence": row.get("attack_confidence"),
            "reason": row.get("reason"),
            "review_required": row.get("needs_review"),
        })
    return pd.DataFrame(rows)


def severity_rank(value: Any) -> int:
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFORMATIONAL": 4,
        "INFO": 4,
        "LOG": 5,
        "UNKNOWN": 6,
    }
    return order.get(clean_text(value).upper(), 6)


def severity_label(row: pd.Series) -> str:
    severity = clean_text(row.get("severity")) or "Unknown"
    return severity


def sort_customer_findings(df: pd.DataFrame) -> pd.DataFrame:
    sorted_df = df.copy()
    sorted_df["_severity_sort"] = sorted_df["severity"].apply(severity_rank) if "severity" in sorted_df.columns else 99
    score_col = "risk_score" if "risk_score" in sorted_df.columns else "cvss"
    sorted_df["_score_sort"] = pd.to_numeric(sorted_df.get(score_col, 0), errors="coerce").fillna(0)
    sorted_df.sort_values(by=["_severity_sort", "_score_sort"], ascending=[True, False], inplace=True)
    sorted_df.drop(columns=["_severity_sort", "_score_sort"], inplace=True)
    return sorted_df


def target_summary(df: pd.DataFrame, max_items: int = 3) -> str:
    assets = [
        clean_text(value)
        for value in df.get("asset", pd.Series(dtype=str)).dropna().tolist()
        if clean_text(value)
    ]
    unique_assets = list(dict.fromkeys(assets))
    if not unique_assets:
        return "Không xác định"
    shown = unique_assets[:max_items]
    suffix = f" và {len(unique_assets) - max_items} mục tiêu khác" if len(unique_assets) > max_items else ""
    return ", ".join(shown) + suffix


def scan_time_summary(df: pd.DataFrame) -> tuple[str, str]:
    scan_times = [
        clean_text(value)
        for value in df.get("scan_time", pd.Series(dtype=str)).dropna().tolist()
        if clean_text(value)
    ]
    completed = [
        clean_text(value)
        for value in df.get("verification_completed_at", pd.Series(dtype=str)).dropna().tolist()
        if clean_text(value)
    ]
    start = min(scan_times) if scan_times else "Không xác định"
    end = max(completed or scan_times) if (completed or scan_times) else rt.utc_now()
    return start, end


def customer_visible_findings(df: pd.DataFrame) -> pd.DataFrame:
    if "verification_status" not in df.columns:
        return sort_customer_findings(df)
    mask = ~df["verification_status"].apply(
        lambda value: normalize_verification_status(value) in FALSE_POSITIVE_STATUSES
    )
    return sort_customer_findings(df[mask].copy())


def customer_detail_text(row: pd.Series) -> str:
    parts = [
        f"Tài sản: {clean_text(row.get('asset')) or 'Không xác định'}",
        f"Vị trí: {first_nonempty(row.get('location'), row.get('url_or_port'), max_length=180) or 'Không xác định'}",
        f"Trạng thái kiểm chứng: {human_verification_status(row.get('verification_status'))}",
    ]
    evidence = evidence_summary(row, max_length=650)
    if evidence:
        parts.append(f"Bằng chứng: {evidence}")
    intel = exploit_summary(row)
    if intel:
        parts.append(f"Thông tin exploit: {intel}")
    return "\n".join(parts)


def customer_solution_text(row: pd.Series) -> str:
    parts = []
    solution = remediation_summary(row, max_length=650)
    if solution:
        parts.append(solution)
    priority = clean_text(row.get("priority"))
    risk_score = clean_text(row.get("risk_score"))
    if priority or risk_score:
        parts.append(f"Ưu tiên xử lý: {priority or 'N/A'}; điểm rủi ro: {risk_score or 'N/A'}.")
    return "\n".join(parts) or "Cần analyst rà soát và xác nhận biện pháp xử lý phù hợp."


def plugin_or_cve(row: pd.Series) -> str:
    values = []
    plugin = clean_text(row.get("plugin_id"))
    if plugin:
        values.append(plugin)
    cves = ", ".join(extract_cves(row.get("cve"), row.get("cve_list")))
    if cves:
        values.append(cves)
    cwes = ", ".join(extract_cwes(row.get("cwe"), row.get("cwe_list")))
    if cwes and not values:
        values.append(cwes)
    return "\n".join(values)


def _customer_formats(workbook):
    return {
        "title": workbook.add_format({
            "bold": True,
            "font_size": 16,
            "font_color": "white",
            "bg_color": "#1F4E78",
            "align": "center",
            "valign": "vcenter",
        }),
        "subtitle": workbook.add_format({
            "bold": True,
            "font_size": 11,
            "font_color": "#1F4E78",
            "align": "center",
            "valign": "vcenter",
        }),
        "section": workbook.add_format({
            "bold": True,
            "font_color": "white",
            "bg_color": "#4472C4",
            "border": 1,
            "align": "left",
            "valign": "vcenter",
        }),
        "label": workbook.add_format({"bold": True, "border": 1, "bg_color": "#D9EAF7", "valign": "vcenter"}),
        "value": workbook.add_format({"border": 1, "text_wrap": True, "valign": "vcenter"}),
        "header": workbook.add_format({
            "bold": True,
            "font_color": "white",
            "bg_color": "#1F4E78",
            "border": 1,
            "align": "center",
            "valign": "vcenter",
            "text_wrap": True,
        }),
        "cell": workbook.add_format({"border": 1, "valign": "top", "text_wrap": True}),
        "center": workbook.add_format({"border": 1, "align": "center", "valign": "top", "text_wrap": True}),
        "critical": workbook.add_format({"border": 1, "bg_color": "#C00000", "font_color": "white", "bold": True, "align": "center", "valign": "top", "text_wrap": True}),
        "high": workbook.add_format({"border": 1, "bg_color": "#F4B183", "bold": True, "align": "center", "valign": "top", "text_wrap": True}),
        "medium": workbook.add_format({"border": 1, "bg_color": "#FFD966", "bold": True, "align": "center", "valign": "top", "text_wrap": True}),
        "low": workbook.add_format({"border": 1, "bg_color": "#A9D18E", "align": "center", "valign": "top", "text_wrap": True}),
        "info": workbook.add_format({"border": 1, "bg_color": "#D9E1F2", "align": "center", "valign": "top", "text_wrap": True}),
        "total": workbook.add_format({"bold": True, "border": 1, "bg_color": "#D9EAD3"}),
        "note": workbook.add_format({"italic": True, "font_color": "#666666", "text_wrap": True}),
    }


def _severity_format(formats: dict[str, Any], severity: Any):
    text = clean_text(severity).upper()
    if text == "CRITICAL":
        return formats["critical"]
    if text == "HIGH":
        return formats["high"]
    if text == "MEDIUM":
        return formats["medium"]
    if text == "LOW":
        return formats["low"]
    return formats["info"]


def write_customer_overview(writer, df: pd.DataFrame, source: str):
    workbook = writer.book
    ws = workbook.add_worksheet("Tổng Quan")
    writer.sheets["Tổng Quan"] = ws
    f = _customer_formats(workbook)
    ws.set_column("A:A", 20)
    ws.set_column("B:B", 14)
    ws.set_column("C:C", 14)
    ws.set_column("D:H", 17)
    ws.set_column("I:P", 12)
    ws.set_row(0, 26)
    ws.set_row(1, 22)

    ws.merge_range("A1:P1", "BÁO CÁO ĐÁNH GIÁ LỖ HỔNG BẢO MẬT", f["title"])
    ws.merge_range("A2:P2", "VULNERABILITY ASSESSMENT REPORT", f["subtitle"])

    scan_start, scan_end = scan_time_summary(df)
    target_text = target_summary(df)
    asset_count = int(df.get("asset", pd.Series(dtype=str)).fillna("").astype(str).str.strip().replace("", pd.NA).dropna().nunique())

    ws.merge_range("A4:H4", "THÔNG TIN MỤC TIÊU", f["section"])
    info_rows = [
        ("Mục tiêu:", target_text),
        ("Số asset:", asset_count),
        ("Nguồn dữ liệu:", Path(source).name),
        ("Thời gian scan:", scan_start),
        ("Thời gian báo cáo:", scan_end),
        ("Ghi chú:", "Bản customer-safe. Public exploit intelligence không phải bằng chứng target đã khai thác được."),
    ]
    for offset, (label, value) in enumerate(info_rows, start=4):
        row = offset
        ws.merge_range(row, 0, row, 2, label, f["label"])
        ws.merge_range(row, 3, row, 7, value, f["value"])

    visible = customer_visible_findings(df)
    ws.merge_range("A13:P13", "THỐNG KÊ LỖ HỔNG", f["section"])
    ws.write_row("A14", ["Mức độ", "Số lượng"], f["header"])
    severity_counts = visible.get("severity", pd.Series(dtype=str)).fillna("Unknown").value_counts()
    severity_rows = ["Critical", "High", "Medium", "Low", "Informational", "Info", "Log", "Unknown"]
    row_num = 14
    severity_start_row = row_num
    total = 0
    for severity in severity_rows:
        count = int(severity_counts.get(severity, 0))
        if count == 0 and severity not in {"Critical", "High", "Medium", "Low"}:
            continue
        ws.write(row_num, 0, severity, _severity_format(f, severity))
        ws.write(row_num, 1, count, f["center"])
        total += count
        row_num += 1
    severity_end_row = row_num - 1
    ws.write(row_num, 0, "TỔNG", f["total"])
    ws.write(row_num, 1, total, f["total"])

    pie = workbook.add_chart({"type": "pie"})
    pie.add_series({
        "name": "Phân bổ lỗ hổng theo mức độ",
        "categories": ["Tổng Quan", severity_start_row, 0, severity_end_row, 0],
        "values": ["Tổng Quan", severity_start_row, 1, severity_end_row, 1],
        "data_labels": {"percentage": True, "leader_lines": True},
    })
    pie.set_title({"name": "Phân bổ lỗ hổng theo mức độ"})
    pie.set_style(10)
    ws.insert_chart("D14", pie, {"x_scale": 0.92, "y_scale": 0.92})

    bar = workbook.add_chart({"type": "column"})
    bar.add_series({
        "name": "Số lượng",
        "categories": ["Tổng Quan", severity_start_row, 0, severity_end_row, 0],
        "values": ["Tổng Quan", severity_start_row, 1, severity_end_row, 1],
        "data_labels": {"value": True},
    })
    bar.set_title({"name": "Số lượng lỗ hổng theo mức độ"})
    bar.set_legend({"none": True})
    bar.set_y_axis({"major_gridlines": {"visible": False}})
    bar.set_style(11)
    ws.insert_chart("I14", bar, {"x_scale": 0.92, "y_scale": 0.92})

    ws.write_row("A32", ["Trạng thái kiểm chứng", "Số lượng"], f["header"])
    status_groups = [
        ("Đã xác nhận trên target", CONFIRMED_STATUSES),
        ("Cần rà soát/chưa kiểm chứng", REVIEW_STATUSES),
        ("Đã loại/không tái hiện", FALSE_POSITIVE_STATUSES),
    ]
    for idx, (label, statuses) in enumerate(status_groups, start=32):
        count = int(df.get("verification_status", pd.Series(dtype=str)).apply(lambda value: normalize_verification_status(value) in statuses).sum())
        ws.write(idx, 0, label, f["cell"])
        ws.write(idx, 1, count, f["center"])

    ws.merge_range("D32:P32", "DIỄN GIẢI", f["section"])
    ws.merge_range(
        "D33:P35",
        "Chỉ các mục có trạng thái REPRODUCED hoặc CONFIRMED_PRESENT mới được xem là bằng chứng target-level. "
        "Các mục còn lại là phát hiện scanner hoặc triage cần rà soát trong phạm vi an toàn.",
        f["note"],
    )


def write_customer_details(writer, df: pd.DataFrame):
    workbook = writer.book
    ws = workbook.add_worksheet("Chi Tiết Lỗ Hổng")
    writer.sheets["Chi Tiết Lỗ Hổng"] = ws
    f = _customer_formats(workbook)

    ws.set_column("A:A", 6)
    ws.set_column("B:B", 14)
    ws.set_column("C:C", 18)
    ws.set_column("D:D", 48)
    ws.set_column("E:E", 72)
    ws.set_column("F:F", 58)
    ws.set_row(0, 26)
    ws.set_row(1, 22)
    ws.merge_range("A1:F1", "DANH SÁCH LỖ HỔNG CHI TIẾT", f["title"])
    ws.merge_range("A2:F2", f"Target: {target_summary(df)}", f["subtitle"])
    headers = ["STT", "Mức Độ", "Plugin/CVE", "Lỗ Hổng", "Chi Tiết", "Giải Pháp"]
    ws.write_row(3, 0, headers, f["header"])
    ws.freeze_panes(4, 0)

    visible = customer_visible_findings(df)
    for idx, (_, row) in enumerate(visible.iterrows(), start=1):
        excel_row = idx + 3
        ws.write_number(excel_row, 0, idx, f["center"])
        ws.write(excel_row, 1, severity_label(row), _severity_format(f, row.get("severity")))
        ws.write(excel_row, 2, plugin_or_cve(row), f["center"])
        ws.write(excel_row, 3, clean_text(row.get("finding_name"), max_length=260), f["cell"])
        ws.write(excel_row, 4, customer_detail_text(row), f["cell"])
        ws.write(excel_row, 5, customer_solution_text(row), f["cell"])
        ws.set_row(excel_row, 118)

    if visible.empty:
        ws.merge_range("A5:F5", "Không có lỗ hổng cần đưa vào báo cáo khách hàng.", f["cell"])


def export_customer_report(df: pd.DataFrame, source: str, output_file: Path):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_df = redact_dataframe(df)
    drop_cols = [column for column in CUSTOMER_DROP_COLUMNS if column in report_df.columns]
    if drop_cols:
        report_df = report_df.drop(columns=drop_cols)
    with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
        write_customer_overview(writer, report_df, source)
        write_customer_details(writer, report_df)


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


def build_cve_intel(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        cves = extract_cves(row.get("cve"), row.get("cve_list"))
        epss_all = {
            item.get("cve"): item
            for item in loads_json_list(row.get("epss_all_json"))
            if isinstance(item, dict)
        }
        sources = [
            item for item in loads_json_list(row.get("exploit_sources_json"))
            if isinstance(item, dict)
        ]
        sources_by_cve = {}
        for source in sources:
            cve = clean_text(source.get("cve")).upper()
            sources_by_cve.setdefault(cve, []).append(source.get("type"))

        for cve in cves:
            epss = epss_all.get(cve, {})
            cve_sources = sorted(set(sources_by_cve.get(cve, [])))
            if {"Exploit-DB", "Metasploit"} & set(cve_sources):
                cve_exploit_status = "PUBLIC_EXPLOIT_AVAILABLE"
            elif "Nuclei" in cve_sources:
                cve_exploit_status = "EXPLOIT_TEMPLATE_AVAILABLE"
            else:
                cve_exploit_status = "NO_PUBLIC_EXPLOIT_FOUND"
            rows.append({
                "cve": cve,
                "finding_name": row.get("finding_name"),
                "asset": row.get("asset"),
                "location": row.get("location"),
                "priority": row.get("priority"),
                "epss": epss.get("epss", 0.0),
                "epss_percentile": epss.get("percentile", 0.0),
                "exploit_sources": ",".join(cve_sources),
                "exploit_status": cve_exploit_status,
                "finding_exploit_status": row.get("exploit_status"),
                "finding_exploit_source_cves": row.get("exploit_source_cves"),
                "match_basis": exploit_match_basis(cve_exploit_status, sources_by_cve.get(cve, [])),
                "finding_match_basis": row.get("exploit_match_basis") or exploit_match_basis(row.get("exploit_status"), sources),
                "finding_match_note": row.get("exploit_match_note") or exploit_match_note(row.get("exploit_status"), sources),
                "finding_context_review_required": row.get("exploit_context_review_required"),
                "finding_context_summary": row.get("exploit_context_summary"),
            })
    return pd.DataFrame(rows)


def build_exploit_intel(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in df.iterrows():
        sources = loads_json_list(row.get("exploit_sources_json"))
        status = clean_text(row.get("exploit_status")).upper()
        has_signal = to_bool(row.get("exploit_available", False)) or bool(sources) or status in {
            "PUBLIC_EXPLOIT_AVAILABLE",
            "EXPLOIT_TEMPLATE_AVAILABLE",
            "INTEL_CHECK_ERROR",
        }
        if not has_signal:
            continue
        if not sources:
            rows.append({
                "finding_name": row.get("finding_name"),
                "asset": row.get("asset"),
                "location": row.get("location"),
                "exploit_status": row.get("exploit_status"),
                "exploit_available": row.get("exploit_available"),
                "matched_cves": row.get("exploit_source_cves"),
                "source_type": "",
                "source_detail": row.get("exploit_evidence"),
                "match_basis": row.get("exploit_match_basis") or exploit_match_basis(row.get("exploit_status"), []),
                "match_note": row.get("exploit_match_note") or exploit_match_note(row.get("exploit_status"), []),
                "context_match": "",
                "context_review_required": row.get("exploit_context_review_required"),
                "context_summary": row.get("exploit_context_summary"),
            })
            continue
        for source in sources:
            if not isinstance(source, dict):
                continue
            rows.append({
                "finding_name": row.get("finding_name"),
                "asset": row.get("asset"),
                "location": row.get("location"),
                "exploit_status": row.get("exploit_status"),
                "exploit_available": row.get("exploit_available"),
                "matched_cves": row.get("exploit_source_cves"),
                "source_type": source.get("type"),
                "source_cve": source.get("cve"),
                "source_detail": source.get("module") or source.get("template") or source.get("title"),
                "match_basis": source.get("match_basis") or row.get("exploit_match_basis") or exploit_match_basis(row.get("exploit_status"), [source]),
                "match_note": source.get("match_note") or row.get("exploit_match_note") or exploit_match_note(row.get("exploit_status"), [source]),
                "context_match": source.get("context_match"),
                "context_review_required": row.get("exploit_context_review_required"),
                "context_summary": row.get("exploit_context_summary"),
            })
    return pd.DataFrame(rows)


def load_zap_instances(customer_safe: bool) -> pd.DataFrame:
    if not ZAP_INSTANCES_FILE.exists():
        return pd.DataFrame()
    df = pd.read_csv(ZAP_INSTANCES_FILE)
    if customer_safe:
        df = redact_dataframe(df)
    columns = [
        "finding_name",
        "severity",
        "asset",
        "location",
        "method",
        "param",
        "scanner_evidence",
        "plugin_id",
        "instance_index",
    ]
    existing = [column for column in columns if column in df.columns]
    return df[existing].copy() if existing else df


def write_sheet(writer, df: pd.DataFrame, sheet_name: str):
    if df is None or df.empty:
        df = pd.DataFrame({"note": ["No data"]})
    df.to_excel(writer, index=False, sheet_name=sheet_name)
    workbook = writer.book
    worksheet = writer.sheets[sheet_name]
    header_fmt = workbook.add_format({
        "bold": True,
        "font_color": "white",
        "bg_color": "#1F4E78",
        "border": 1,
        "align": "center",
        "valign": "vcenter",
    })
    for idx, column in enumerate(df.columns):
        worksheet.write(0, idx, column, header_fmt)
        col_lower = str(column).lower()
        width = 22
        if any(term in col_lower for term in ["description", "evidence", "solution", "reason", "json"]):
            width = 55
        elif any(term in col_lower for term in ["priority", "score", "cvss", "epss"]):
            width = 14
        worksheet.set_column(idx, idx, width)
    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(0, 0, len(df), max(len(df.columns) - 1, 0))


def export_one_report(df: pd.DataFrame, source: str, output_file: Path, customer_safe: bool):
    if customer_safe:
        export_customer_report(df, source, output_file)
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_df = df.copy()
    report_df = sort_findings(report_df)

    sensitive = report_df[
        report_df["sensitive_evidence"].apply(to_bool)
    ].copy() if "sensitive_evidence" in report_df.columns else pd.DataFrame()

    with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:
        write_sheet(writer, build_summary(report_df, source, customer_safe), "Executive Summary")
        write_sheet(writer, build_action_plan(report_df), "Findings")
        write_sheet(writer, build_status_view(report_df, CONFIRMED_STATUSES), "Verified Findings")
        write_sheet(writer, build_status_view(report_df, REVIEW_STATUSES), "Needs Review")
        write_sheet(writer, build_status_view(report_df, FALSE_POSITIVE_STATUSES), "False Positives")
        write_sheet(writer, report_df, "Raw Findings")
        write_sheet(writer, build_cve_intel(report_df), "CVE Intel")
        write_sheet(writer, build_exploit_intel(report_df), "Exploit Intel")
        write_sheet(writer, build_mapping_review(report_df), "Mapping Review")
        write_sheet(writer, load_zap_instances(customer_safe), "ZAP Instances")
        write_sheet(writer, sensitive, "Sensitive Evidence")


def export_clean_report():
    print("📊 [EXCEL] Exporting multi-sheet reports...")
    try:
        df, source = load_findings()
    except Exception as exc:
        print(f"❌ LỖI: Không có dữ liệu: {exc}")
        raise SystemExit(1)

    df = refresh_risk_columns(df)
    export_one_report(df, source, OUTPUT_FILE, customer_safe=False)
    export_one_report(df, source, CUSTOMER_OUTPUT_FILE, customer_safe=True)

    print(f"✅ [EXCEL] Internal report: {OUTPUT_FILE}")
    print(f"✅ [EXCEL] Customer-safe report: {CUSTOMER_OUTPUT_FILE}")


if __name__ == "__main__":
    export_clean_report()
