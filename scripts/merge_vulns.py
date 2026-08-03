#!/usr/bin/env python3
"""Merge normalized ZAP/OpenVAS findings into one canonical CSV."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import CANONICAL_FINDING_COLUMNS, normalize_dataframe_schema
except ImportError:
    import runtime_context as rt
    from schema_utils import CANONICAL_FINDING_COLUMNS, normalize_dataframe_schema


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
        zap = normalize_dataframe_schema(pd.read_csv(zap_path))
        print(f"ZAP findings: {len(zap)}")
        frames.append(zap)
    else:
        print("⚠️  ZAP findings not found — merging without ZAP data.")

    if openvas_path.exists():
        openvas = normalize_dataframe_schema(pd.read_csv(openvas_path))
        print(f"OpenVAS findings: {len(openvas)}")
        frames.append(openvas)
    else:
        print("⚠️  OpenVAS findings not found — merging without OpenVAS data.")

    if not frames:
        raise FileNotFoundError(f"Missing all normalized scanner inputs: {zap_path}, {openvas_path}")

    combined = normalize_dataframe_schema(pd.concat(frames, ignore_index=True))
    combined.drop_duplicates(
        subset=["scanner", "asset", "location", "finding_name"],
        keep="first",
        inplace=True,
    )

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
