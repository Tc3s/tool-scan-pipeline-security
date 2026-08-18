#!/usr/bin/env python3
"""Merge normalized ZAP/OpenVAS findings into one canonical CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import CANONICAL_FINDING_COLUMNS, extract_cves, normalize_dataframe_schema
except ImportError:
    import runtime_context as rt
    from schema_utils import CANONICAL_FINDING_COLUMNS, extract_cves, normalize_dataframe_schema


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

    combined = normalize_dataframe_schema(pd.concat(frames, ignore_index=True))
    
    kept_rows = []
    for _, row in combined.iterrows():
        is_duplicate = False
        asset = str(row.get("asset", "")).strip().lower()
        loc = str(row.get("location", "")).strip().lower()
        name = str(row.get("finding_name", "")).strip().lower()
        cves = set(extract_cves(row.get("cve"), row.get("cve_list")))
        
        for kept in kept_rows:
            if asset != str(kept.get("asset", "")).strip().lower() or loc != str(kept.get("location", "")).strip().lower():
                continue
                
            kept_cves = set(extract_cves(kept.get("cve"), kept.get("cve_list")))
            kept_name = str(kept.get("finding_name", "")).strip().lower()
            scanner = str(row.get("scanner", "")).strip().lower()
            kept_scanner = str(kept.get("scanner", "")).strip().lower()
            plugin_id = str(row.get("plugin_id", "")).strip()
            kept_plugin_id = str(kept.get("plugin_id", "")).strip()
            
            # Case 1: Shared CVE on the same asset & location
            if cves and kept_cves and not cves.isdisjoint(kept_cves):
                is_duplicate = True
                break
                
            # Case 2: Same scanner and same plugin ID on the same asset & location
            if scanner and kept_scanner and scanner == kept_scanner and plugin_id and kept_plugin_id and plugin_id == kept_plugin_id:
                is_duplicate = True
                break

            # Case 3: High finding name similarity on the exact same asset & location
            if difflib.SequenceMatcher(None, name, kept_name).ratio() >= 0.8:
                is_duplicate = True
                break
                
        if not is_duplicate:
            kept_rows.append(row)
            
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
