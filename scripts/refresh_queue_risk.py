#!/usr/bin/env python3
"""Recalculate risk fields for an existing validation queue."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.calculate_risk_priority import calculate_risk_for_row
    from scripts.schema_utils import normalize_dataframe_schema
except ImportError:
    import runtime_context as rt
    from calculate_risk_priority import calculate_risk_for_row
    from schema_utils import normalize_dataframe_schema


def refresh_queue_risk(input_file: str | Path, output_file: str | Path | None = None) -> int:
    input_path = Path(input_file)
    output_path = Path(output_file) if output_file else input_path
    df = normalize_dataframe_schema(pd.read_csv(input_path))
    risk_rows = [calculate_risk_for_row(row) for _, row in df.iterrows()]
    df["risk_score"] = [item["risk_score"] for item in risk_rows]
    df["priority"] = [item["priority"] for item in risk_rows]
    df["risk_reason"] = [item["risk_reason"] for item in risk_rows]
    df["risk_components_json"] = [item["risk_components_json"] for item in risk_rows]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    return len(df)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh queue risk fields from current verification status.")
    parser.add_argument("--input-file", default=str(rt.output_dir() / "vuln_validation_queue.csv"))
    parser.add_argument("--output-file")
    args = parser.parse_args(argv)
    count = refresh_queue_risk(args.input_file, args.output_file)
    print(f"[RISK] Refreshed {count} queue rows: {args.output_file or args.input_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
