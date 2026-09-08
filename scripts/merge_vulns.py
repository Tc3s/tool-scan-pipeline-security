#!/usr/bin/env python3
"""Merge normalized ZAP/OpenVAS findings into one canonical CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import (
        CANONICAL_FINDING_COLUMNS,
        extract_cves,
        extract_cwes,
        ids_to_csv,
        loads_json_list,
        normalize_dataframe_schema,
        unique_preserve_order,
        values_to_json,
    )
except ImportError:
    import runtime_context as rt
    from schema_utils import (
        CANONICAL_FINDING_COLUMNS,
        extract_cves,
        extract_cwes,
        ids_to_csv,
        loads_json_list,
        normalize_dataframe_schema,
        unique_preserve_order,
        values_to_json,
    )


def merge_vulns(
    zap_file: str | Path | None = None,
    openvas_file: str | Path | None = None,
    output_file: str | Path | None = None,
) -> int:
    zap_path = Path(zap_file) if zap_file else rt.normalized_dir() / "zap_findings.csv"
    openvas_path = Path(openvas_file) if openvas_file else rt.normalized_dir() / "openvas_findings.csv"
    output_path = Path(output_file) if output_file else rt.output_dir() / "vuln_raw.csv"

    frames = []
    if zap_path.exists():
        try:
            zap = normalize_dataframe_schema(pd.read_csv(zap_path))
            print(f"ZAP findings: {len(zap)}")
            frames.append(zap)
        except pd.errors.EmptyDataError:
            print("⚠️  ZAP findings file is empty — merging without ZAP data.")
    else:
        print("⚠️  ZAP findings not found — merging without ZAP data.")

    if openvas_path.exists():
        try:
            openvas = normalize_dataframe_schema(pd.read_csv(openvas_path))
            print(f"OpenVAS findings: {len(openvas)}")
            frames.append(openvas)
        except pd.errors.EmptyDataError:
            print("⚠️  OpenVAS findings file is empty — merging without OpenVAS data.")
    else:
        print("⚠️  OpenVAS findings not found — merging without OpenVAS data.")

    if not frames:
        raise FileNotFoundError(f"Missing all normalized scanner inputs: {zap_path}, {openvas_path}")

    import difflib

    def _safe_float(val: object) -> float:
        try:
            return float(val) if val is not None and str(val).strip() != "" else 0.0
        except (ValueError, TypeError):
            return 0.0

    def _are_incompatible_vuln_types(name1: str, name2: str) -> bool:
        """Check if two finding names represent fundamentally incompatible vulnerability classes.
        
        Prevents false deduplication (e.g. merging SSRF with Authentication Bypass,
        or Buffer Overread with Use-After-Free).
        """
        incompatible_pairs = [
            ("ssrf", "bypass"),
            ("ssrf", "access control"),
            ("ssrf", "traversal"),
            ("buffer overread", "uaf"),
            ("buffer overread", "use-after-free"),
            ("buffer overread", "overflow"),
            ("integer overflow", "bypass"),
            ("integer overflow", "ssrf"),
            ("integer overflow", "access control"),
            ("authentication bypass", "information disclosure"),
            ("authentication bypass", "dos"),
            ("dos", "remote code execution"),
            ("dos", "rce"),
            ("denial of service", "remote code execution"),
        ]
        n1, n2 = name1.lower(), name2.lower()
        for kw1, kw2 in incompatible_pairs:
            if (kw1 in n1 and kw2 in n2) or (kw2 in n1 and kw1 in n2):
                return True
        return False

    def _enrich_existing_finding(kept: dict[str, object], row: dict[str, object]) -> None:
        """Perform union enrichment when two findings are legitimately merged.
        
        Preserves all CVEs, CWEs, URLs, retains maximum CVSS/severity, and sums instance counts.
        """
        # 1. Union CVEs
        c1 = extract_cves(kept.get("cve"), kept.get("cve_list"))
        c2 = extract_cves(row.get("cve"), row.get("cve_list"))
        all_cves = unique_preserve_order(c1 + c2)
        if all_cves:
            kept["cve"] = ids_to_csv(all_cves)
            kept["cve_list"] = values_to_json(all_cves)

        # 2. Union CWEs
        cw1 = extract_cwes(kept.get("cwe"), kept.get("cwe_list"))
        cw2 = extract_cwes(row.get("cwe"), row.get("cwe_list"))
        all_cwes = unique_preserve_order(cw1 + cw2)
        if all_cwes:
            kept["cwe"] = ids_to_csv(all_cwes)
            kept["cwe_list"] = values_to_json(all_cwes)

        # 3. Preserve Highest CVSS & Severity
        k_cvss = _safe_float(kept.get("cvss"))
        r_cvss = _safe_float(row.get("cvss"))
        if r_cvss > k_cvss:
            kept["cvss"] = r_cvss
            if row.get("severity"):
                kept["severity"] = row.get("severity")

        # 4. Union Affected URLs
        urls1 = loads_json_list(kept.get("affected_urls_json"))
        urls2 = loads_json_list(row.get("affected_urls_json"))
        all_urls = unique_preserve_order(urls1 + urls2)
        if all_urls:
            kept["affected_urls_json"] = values_to_json(all_urls)

        # 5. Instance count
        try:
            cnt1 = int(kept.get("instance_count") or 1)
        except (ValueError, TypeError):
            cnt1 = 1
        try:
            cnt2 = int(row.get("instance_count") or 1)
        except (ValueError, TypeError):
            cnt2 = 1
        kept["instance_count"] = max(cnt1 + cnt2, 1)

        # 6. Fill empty evidence or solution
        if not kept.get("scanner_evidence") and row.get("scanner_evidence"):
            kept["scanner_evidence"] = row.get("scanner_evidence")
        if not kept.get("evidence") and row.get("evidence"):
            kept["evidence"] = row.get("evidence")
        if not kept.get("scanner_solution") and row.get("scanner_solution"):
            kept["scanner_solution"] = row.get("scanner_solution")
        if not kept.get("solution") and row.get("solution"):
            kept["solution"] = row.get("solution")
        if not kept.get("description") and row.get("description"):
            kept["description"] = row.get("description")

    combined = normalize_dataframe_schema(pd.concat(frames, ignore_index=True))
    
    kept_rows: list[dict[str, object]] = []
    for _, row in combined.iterrows():
        row_dict = row.to_dict()
        is_duplicate = False
        asset = str(row_dict.get("asset", "")).strip().lower()
        loc = str(row_dict.get("location", "")).strip().lower()
        name = str(row_dict.get("finding_name", "")).strip().lower()
        cves = set(extract_cves(row_dict.get("cve"), row_dict.get("cve_list")))
        scanner = str(row_dict.get("scanner", "")).strip().lower()
        plugin_id = str(row_dict.get("plugin_id", "")).strip()
        
        for kept in kept_rows:
            if asset != str(kept.get("asset", "")).strip().lower() or loc != str(kept.get("location", "")).strip().lower():
                continue
                
            kept_cves = set(extract_cves(kept.get("cve"), kept.get("cve_list")))
            kept_name = str(kept.get("finding_name", "")).strip().lower()
            kept_scanner = str(kept.get("scanner", "")).strip().lower()
            kept_plugin_id = str(kept.get("plugin_id", "")).strip()
            
            # Case 1: Shared CVE on the same asset & location
            if cves and kept_cves and not cves.isdisjoint(kept_cves):
                is_duplicate = True
                _enrich_existing_finding(kept, row_dict)
                break
                
            # Case 2: Same scanner and same plugin ID on the same asset & location
            if scanner and kept_scanner and scanner == kept_scanner and plugin_id and kept_plugin_id and plugin_id == kept_plugin_id:
                is_duplicate = True
                _enrich_existing_finding(kept, row_dict)
                break

            # If both findings have non-empty CVE sets and they are completely disjoint,
            # they are distinct security advisories / CVE vulnerabilities -> NEVER merge them
            if cves and kept_cves and cves.isdisjoint(kept_cves):
                continue

            # If the finding names represent incompatible vulnerability types -> NEVER merge them
            if _are_incompatible_vuln_types(name, kept_name):
                continue

            # Case 3: High finding name similarity on the exact same asset & location (no conflicting CVEs)
            if difflib.SequenceMatcher(None, name, kept_name).ratio() >= 0.85:
                is_duplicate = True
                _enrich_existing_finding(kept, row_dict)
                break
                
        if not is_duplicate:
            kept_rows.append(row_dict)
            
    combined = pd.DataFrame(kept_rows) if kept_rows else pd.DataFrame(columns=combined.columns)

    front_cols = [column for column in CANONICAL_FINDING_COLUMNS if column in combined.columns]
    remaining_cols = [column for column in combined.columns if column not in front_cols]
    combined = combined[front_cols + remaining_cols]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_path, index=False)
    print(f"✅ Merged → {len(combined)} unique findings in {output_path}")
    return len(combined)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge normalized vulnerability CSV files.")
    parser.add_argument("--zap", help="Path to normalized ZAP CSV")
    parser.add_argument("--openvas", help="Path to normalized OpenVAS CSV")
    parser.add_argument("--output", help="Output CSV path")
    args = parser.parse_args(argv)

    try:
        merge_vulns(args.zap, args.openvas, args.output)
    except Exception as exc:
        print(f"❌ Merge failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
