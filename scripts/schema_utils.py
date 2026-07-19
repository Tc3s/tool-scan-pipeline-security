#!/usr/bin/env python3
"""Shared schema, CVE parsing, and redaction helpers for the VA pipeline."""

from __future__ import annotations

import json
import math
import re
from typing import Any, Iterable


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-?\d+\b", re.IGNORECASE)

CANONICAL_FINDING_COLUMNS = [
    "scanner",
    "scan_time",
    "asset",
    "asset_type",
    "location",
    "url_or_port",
    "finding_name",
    "severity",
    "cvss",
    "cve",
    "cve_list",
    "cwe",
    "cwe_list",
    "plugin_id",
    "description",
    "scanner_evidence",
    "scanner_solution",
    "evidence",
    "solution",
    "raw_reference",
    "instance_count",
    "affected_urls_json",
]

VERIFICATION_STATUSES = {
    "NOT_VERIFIED",
    "CONFIRMED_PRESENT",
    "REPRODUCED",
    "CHECKED_NOT_REPRODUCED",
    "FALSE_POSITIVE",
    "NEEDS_MANUAL_REVIEW",
    "SKIPPED_SAFE_MODE",
    "ERROR",
}

EXPLOIT_STATUSES = {
    "EXPLOIT_INTEL_NOT_RUN",
    "PUBLIC_EXPLOIT_AVAILABLE",
    "EXPLOIT_TEMPLATE_AVAILABLE",
    "NO_PUBLIC_EXPLOIT_FOUND",
    "NO_CVE_ID",
    "INTEL_CHECK_ERROR",
}

SENSITIVE_QUERY_KEYS = (
    "password",
    "passwd",
    "pwd",
    "username",
    "user",
    "token",
    "csrf",
    "xsrf",
    "secret",
    "api_key",
    "apikey",
    "sessionid",
    "jsessionid",
    "phpsessid",
    "sid",
    "access_token",
    "access-token",
    "auth_token",
    "auth-token",
)

SENSITIVE_QUERY_PATTERN = re.compile(
    r"(?i)(?:[?&;]|\b)(" + "|".join(re.escape(key) for key in SENSITIVE_QUERY_KEYS) + r")\s*="
)

URL_BASIC_AUTH_PATTERN = re.compile(r"(?i)(https?://)([^:/@\s]+):([^@/\s]+)@")

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(cookie|authorization|x-api-key)\s*:\s*[^\r\n;]+"),
    re.compile(
        r"(?i)\b("
        + "|".join(re.escape(key) for key in SENSITIVE_QUERY_KEYS)
        + r")\s*=\s*[^&\s;\"'\]\}]+"
    ),
    re.compile(r"(?i)\b(password|passwd|pwd)\s*:\s*[^,\s;]+"),
    re.compile(r"(?i)\b(password)\s+\"[^\"]+\""),
    re.compile(r"(?i)\b(root|admin|tomcat|postgres|msfadmin|user|service|vnc)\s*:\s*[^,\s]+"),
]

SENSITIVE_TERMS = re.compile(
    r"(?i)\b(password|passwd|pwd|username|credential|cookie|token|csrf|xsrf|"
    r"client[_-]?secret|api[_-]?key|sessionid|jsessionid|phpsessid|"
    r"access[_-]?token|auth[_-]?token|root:root|msfadmin|postgres:postgres|"
    r"tomcat-users|/etc/passwd)\b"
)


def is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    if isinstance(value, str):
        return value.strip() == "" or value.strip().lower() in {"nan", "none", "null"}
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def clean_text(value: Any, max_length: int | None = None) -> str:
    if is_empty(value):
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split()).strip()
    if max_length is not None and len(text) > max_length:
        return text[: max_length - 3].rstrip() + "..."
    return text


def first_nonempty(*values: Any, max_length: int | None = None) -> str:
    for value in values:
        text = clean_text(value, max_length=max_length)
        if text:
            return text
    return ""


def unique_preserve_order(values: Iterable[Any]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        text = clean_text(value)
        if not text:
            continue
        key = text.upper()
        if key not in seen:
            seen.add(key)
            result.append(text)
    return result


def extract_cves(*values: Any) -> list[str]:
    found: list[str] = []
    for value in values:
        if is_empty(value):
            continue
        if isinstance(value, (list, tuple, set)):
            found.extend(extract_cves(*value))
            continue
        if isinstance(value, str) and value.strip().startswith("["):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    found.extend(extract_cves(*parsed))
                    continue
            except json.JSONDecodeError:
                pass
        found.extend(match.upper() for match in CVE_RE.findall(str(value)))
    return unique_preserve_order(found)


def extract_cwes(*values: Any) -> list[str]:
    found: list[str] = []
    for value in values:
        if is_empty(value):
            continue
        if isinstance(value, (list, tuple, set)):
            found.extend(extract_cwes(*value))
            continue
        if isinstance(value, str) and value.strip().startswith("["):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    found.extend(extract_cwes(*parsed))
                    continue
            except json.JSONDecodeError:
                pass
        for match in CWE_RE.findall(str(value)):
            digits = re.sub(r"(?i)^CWE-?", "", match)
            found.append(f"CWE-{digits}")
    return unique_preserve_order(found)


def ids_to_csv(values: Iterable[Any]) -> str:
    return ",".join(unique_preserve_order(values))


def values_to_json(values: Iterable[Any]) -> str:
    return json.dumps(unique_preserve_order(values), ensure_ascii=False)


def loads_json_list(value: Any) -> list[Any]:
    if is_empty(value):
        return []
    if isinstance(value, list):
        return value
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def loads_json_dict(value: Any) -> dict[str, Any]:
    if is_empty(value):
        return {}
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if is_empty(value):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "available"}


def legacy_status_to_exploit_status(status: Any) -> str:
    status_text = clean_text(status).upper()
    mapping = {
        "WEAPONIZED": "PUBLIC_EXPLOIT_AVAILABLE",
        "POTENTIAL": "NO_PUBLIC_EXPLOIT_FOUND",
        "SKIPPED_NO_CVE": "NO_CVE_ID",
    }
    if status_text in EXPLOIT_STATUSES:
        return status_text
    return mapping.get(status_text, status_text or "EXPLOIT_INTEL_NOT_RUN")


def normalize_verification_status(status: Any) -> str:
    status_text = clean_text(status).upper()
    if status_text in VERIFICATION_STATUSES:
        return status_text
    legacy = {
        "CHECKED_NO_EXPLOIT": "CHECKED_NOT_REPRODUCED",
        "NOT_REPRODUCED": "CHECKED_NOT_REPRODUCED",
        "CONFIRMED_INFRA_NO_EXPLOIT": "CONFIRMED_PRESENT",
        "VERIFIED": "CONFIRMED_PRESENT",
    }
    return legacy.get(status_text, "NOT_VERIFIED")


def has_sensitive_content(*values: Any) -> bool:
    for value in values:
        if is_empty(value):
            continue
        text = str(value)
        if (
            SENSITIVE_TERMS.search(text)
            or SENSITIVE_QUERY_PATTERN.search(text)
            or URL_BASIC_AUTH_PATTERN.search(text)
        ):
            return True
    return False


def redact_sensitive(value: Any) -> Any:
    if is_empty(value) or not isinstance(value, str):
        return value
    text = URL_BASIC_AUTH_PATTERN.sub(r"\1[REDACTED]:[REDACTED]@", value)
    replacements = [
        (SENSITIVE_PATTERNS[0], lambda m: f"{m.group(1)}: [REDACTED]"),
        (SENSITIVE_PATTERNS[1], lambda m: f"{m.group(1)}=[REDACTED]"),
        (SENSITIVE_PATTERNS[2], lambda m: f"{m.group(1)}: [REDACTED]"),
        (SENSITIVE_PATTERNS[3], lambda m: f'{m.group(1)} "[REDACTED]"'),
        (SENSITIVE_PATTERNS[4], lambda m: f"{m.group(1)}:******"),
    ]
    for pattern, repl in replacements:
        text = pattern.sub(repl, text)
    return text


def redact_sensitive_deep(value: Any) -> Any:
    """Redact sensitive strings inside nested JSON-like structures."""
    if isinstance(value, str):
        return redact_sensitive(value)
    if isinstance(value, list):
        return [redact_sensitive_deep(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_deep(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_sensitive_deep(item) for key, item in value.items()}
    return value


def normalize_dataframe_schema(df):
    """Return a copy with canonical columns while preserving legacy columns."""
    import pandas as pd

    df = df.copy()
    if "location" not in df.columns and "url_or_port" in df.columns:
        df["location"] = df["url_or_port"]
    if "url_or_port" not in df.columns and "location" in df.columns:
        df["url_or_port"] = df["location"]

    if "scanner_evidence" not in df.columns:
        df["scanner_evidence"] = ""
    df["scanner_evidence"] = df.apply(
        lambda row: first_nonempty(row.get("scanner_evidence"), row.get("evidence"), row.get("description"))
        or f"Scanner reported finding without detailed evidence text: {first_nonempty(row.get('finding_name'), row.get('raw_reference'))}",
        axis=1,
    )

    if "scanner_solution" not in df.columns:
        df["scanner_solution"] = ""
    df["scanner_solution"] = df.apply(
        lambda row: first_nonempty(row.get("scanner_solution"), row.get("solution"), row.get("evidence_solution")),
        axis=1,
    )

    if "evidence" not in df.columns:
        df["evidence"] = df["scanner_evidence"]
    else:
        df["evidence"] = df.apply(lambda row: first_nonempty(row.get("evidence"), row.get("scanner_evidence")), axis=1)

    if "solution" not in df.columns:
        df["solution"] = df["scanner_solution"]
    else:
        df["solution"] = df.apply(lambda row: first_nonempty(row.get("solution"), row.get("scanner_solution")), axis=1)

    if "cve" not in df.columns:
        df["cve"] = ""
    df["cve"] = df["cve"].fillna("").astype(str).apply(lambda value: ids_to_csv(extract_cves(value)))
    df["cve_list"] = df.apply(lambda row: values_to_json(extract_cves(row.get("cve"), row.get("cve_list"))), axis=1)

    if "cwe" not in df.columns:
        df["cwe"] = ""
    df["cwe"] = df["cwe"].fillna("").astype(str).apply(lambda value: ids_to_csv(extract_cwes(value)))
    df["cwe_list"] = df.apply(lambda row: values_to_json(extract_cwes(row.get("cwe"), row.get("cwe_list"))), axis=1)

    if "exploit_status" not in df.columns:
        if "agent_status" in df.columns:
            df["exploit_status"] = df["agent_status"]
        else:
            df["exploit_status"] = df.apply(
                lambda row: "EXPLOIT_INTEL_NOT_RUN"
                if extract_cves(row.get("cve"), row.get("cve_list"))
                else "NO_CVE_ID",
                axis=1,
            )
    df["exploit_status"] = df["exploit_status"].apply(legacy_status_to_exploit_status)
    df["exploit_status"] = df.apply(
        lambda row: "EXPLOIT_INTEL_NOT_RUN"
        if row.get("exploit_status") == "NO_CVE_ID" and extract_cves(row.get("cve"), row.get("cve_list"))
        else row.get("exploit_status"),
        axis=1,
    )

    if "verification_status" not in df.columns:
        df["verification_status"] = "NOT_VERIFIED"
    df["verification_status"] = df["verification_status"].apply(normalize_verification_status)

    for column, default in {
        "exploit_available": False,
        "exploit_sources_json": "[]",
        "exploit_source_cves": "",
        "exploit_match_basis": "",
        "exploit_match_note": "",
        "exploit_context_review_required": False,
        "exploit_context_summary": "",
        "epss_lookup_status": "",
        "exploit_evidence": "",
        "verification_evidence": "",
        "verification_method": "",
        "verification_command": "",
        "verification_error": "",
        "verification_confidence": "",
        "verification_started_at": "",
        "verification_completed_at": "",
        "verification_safe_mode": True,
        "risk_reason": "",
        "risk_components_json": "{}",
        "attack_tactics_json": "[]",
        "attack_techniques_json": "[]",
        "mapping_type": "",
        "raw_reference": "",
        "instance_count": 1,
        "affected_urls_json": "[]",
    }.items():
        if column not in df.columns:
            df[column] = default

    df["sensitive_evidence"] = df.apply(
        lambda row: has_sensitive_content(
            row.get("location"),
            row.get("url_or_port"),
            row.get("affected_urls_json"),
            row.get("description"),
            row.get("scanner_evidence"),
            row.get("scanner_solution"),
            row.get("verification_evidence"),
            row.get("exploit_evidence"),
        ),
        axis=1,
    )

    for column in CANONICAL_FINDING_COLUMNS:
        if column not in df.columns:
            df[column] = ""

    leading = [c for c in CANONICAL_FINDING_COLUMNS if c in df.columns]
    rest = [c for c in df.columns if c not in leading]
    return df[leading + rest]


def priority_sort_key(priority: Any) -> int:
    text = clean_text(priority).upper()
    match = re.match(r"P(\d+)", text)
    return int(match.group(1)) if match else 99
