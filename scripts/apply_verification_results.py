#!/usr/bin/env python3
"""Validate generated verifier results and apply them to the queue CSV."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

try:
    from scripts import runtime_context as rt
    from scripts.calculate_risk_priority import calculate_risk_for_row
    from scripts.schema_utils import normalize_dataframe_schema, normalize_verification_status
    from scripts.verification_contract import (
        APPLICABLE_RESULT_STATUSES,
        ContractError,
        VERIFICATION_UPDATE_COLUMNS,
        finding_id,
        validate_result_record,
        write_json,
    )
except ImportError:
    import runtime_context as rt
    from calculate_risk_priority import calculate_risk_for_row
    from schema_utils import normalize_dataframe_schema, normalize_verification_status
    from verification_contract import (
        APPLICABLE_RESULT_STATUSES,
        ContractError,
        VERIFICATION_UPDATE_COLUMNS,
        finding_id,
        validate_result_record,
        write_json,
    )


DEFAULT_QUEUE_FILE = rt.output_dir() / "vuln_validation_queue.csv"
DEFAULT_RESULTS_FILE = rt.verification_results_file()
RISK_UPDATE_COLUMNS = ["risk_score", "priority", "risk_reason", "risk_components_json"]


def queue_finding_ids(df: pd.DataFrame) -> dict[str, int]:
    return {
        finding_id(row, ordinal): idx
        for ordinal, (idx, row) in enumerate(df.iterrows(), start=1)
    }


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ContractError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(record, dict):
                raise ContractError(f"{path}:{line_no}: result record must be an object.")
            records.append(record)
    return records


def validate_results(raw_records: list[dict[str, Any]], allowed_ids: set[str]) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    errors: list[str] = []
    for ordinal, record in enumerate(raw_records, start=1):
        try:
            item = validate_result_record(record, allowed_ids)
            if item["finding_id"] in seen:
                raise ContractError(f"duplicate finding_id: {item['finding_id']}")
            seen.add(item["finding_id"])
            validated.append(item)
        except ContractError as exc:
            errors.append(f"record {ordinal}: {exc}")
    if errors:
        raise ContractError("; ".join(errors))
    return validated


def _ensure_update_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    defaults = {
        "verification_status": "NOT_VERIFIED",
        "verification_evidence": "",
        "verification_method": "",
        "verification_command": "",
        "verification_error": "",
        "verification_confidence": "",
        "verification_started_at": "",
        "verification_completed_at": "",
        "verification_safe_mode": True,
        "verification_run_id": "",
        "verification_result_id": "",
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default
    return df


def apply_results(
    *,
    queue_file: str | Path = DEFAULT_QUEUE_FILE,
    results_file: str | Path = DEFAULT_RESULTS_FILE,
    output_file: str | Path | None = None,
    allow_overwrite: bool = False,
) -> dict[str, Any]:
    queue_path = Path(queue_file)
    results_path = Path(results_file)
    output_path = Path(output_file) if output_file else queue_path

    if not queue_path.exists():
        raise ContractError(f"Queue file not found: {queue_path}")
    if not results_path.exists():
        raise ContractError(f"Verification results file not found: {results_path}")

    df = normalize_dataframe_schema(pd.read_csv(queue_path))
    df = _ensure_update_columns(df)
    id_to_index = queue_finding_ids(df)
    raw_records = read_jsonl(results_path)
    results = validate_results(raw_records, set(id_to_index))
    if not results:
        raise ContractError("No verification result records were provided.")

    stable_update_columns = set(VERIFICATION_UPDATE_COLUMNS) | set(RISK_UPDATE_COLUMNS)
    protected_before = df[[c for c in df.columns if c not in stable_update_columns]].copy(deep=True)
    overwrite_errors: list[str] = []
    counts: dict[str, int] = {}

    for result in results:
        idx = id_to_index[result["finding_id"]]
        current_status = normalize_verification_status(df.at[idx, "verification_status"])
        if current_status in APPLICABLE_RESULT_STATUSES and not allow_overwrite:
            overwrite_errors.append(f"{result['finding_id']} already has terminal status {current_status}")
            continue

        df.at[idx, "verification_status"] = result["status"]
        df.at[idx, "verification_evidence"] = result["evidence"]
        df.at[idx, "verification_method"] = result["method"]
        df.at[idx, "verification_command"] = result["command"]
        df.at[idx, "verification_error"] = result["error"]
        df.at[idx, "verification_confidence"] = result["confidence"]
        df.at[idx, "verification_started_at"] = result["started_at"]
        df.at[idx, "verification_completed_at"] = result["completed_at"] or rt.utc_now()
        df.at[idx, "verification_safe_mode"] = result["safe_mode"]
        df.at[idx, "verification_run_id"] = rt.run_dir().name
        df.at[idx, "verification_result_id"] = result["finding_id"]
        counts[result["status"]] = counts.get(result["status"], 0) + 1

    if overwrite_errors:
        raise ContractError("; ".join(overwrite_errors))

    risk_rows = [calculate_risk_for_row(row) for _, row in df.iterrows()]
    df["risk_score"] = [item["risk_score"] for item in risk_rows]
    df["priority"] = [item["priority"] for item in risk_rows]
    df["risk_reason"] = [item["risk_reason"] for item in risk_rows]
    df["risk_components_json"] = [item["risk_components_json"] for item in risk_rows]

    protected_after = df[[c for c in protected_before.columns]].copy(deep=True)
    if not protected_before.fillna("").astype(str).equals(protected_after.fillna("").astype(str)):
        raise ContractError("Protected scanner/risk/intel columns changed while applying verification results.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    audit = {
        "schema_version": "1.0",
        "applied_at": rt.utc_now(),
        "queue_file": rt.display_path(queue_path),
        "results_file": rt.display_path(results_path),
        "output_file": rt.display_path(output_path),
        "result_count": len(results),
        "status_counts": dict(sorted(counts.items())),
        "queue_sha256_after": rt.file_sha256(output_path),
    }
    write_json(rt.verification_dir() / "applied_results_summary.json", audit)
    return audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply verified JSONL evidence to the validation queue.")
    parser.add_argument("--queue-file", default=str(DEFAULT_QUEUE_FILE))
    parser.add_argument("--results-file", default=str(DEFAULT_RESULTS_FILE))
    parser.add_argument("--output-file")
    parser.add_argument("--allow-overwrite", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        summary = apply_results(
            queue_file=args.queue_file,
            results_file=args.results_file,
            output_file=args.output_file,
            allow_overwrite=args.allow_overwrite,
        )
    except ContractError as exc:
        print(f"[APPLY] FAIL: {exc}")
        return 1

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(f"[APPLY] PASS applied {summary['result_count']} verification results")
        for status, count in summary["status_counts"].items():
            print(f"  - {status}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
