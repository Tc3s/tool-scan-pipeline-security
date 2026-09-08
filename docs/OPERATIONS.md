# VA Pipeline Operations

This runbook describes the controlled operating flow. Runtime artifacts should
live outside committed source by setting `VA_RUN_DIR`.

## Runtime Layout

Recommended per-run layout:

```bash
export VA_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
export VA_RUN_DIR="$PWD/runs/$VA_RUN_ID"
```

If `VA_RUN_DIR` is not set, the pipeline automatically creates a timestamped run directory under `runs/run_YYYYMMDD_HHMMSS/` (or static fallback `data/` if `VA_USE_STATIC_DATA_DIR=true`).

## Standard Flow

1. Put raw scanner inputs under `$VA_RUN_DIR/raw/` (if using Option 2: Process Only).
2. For Active Scanning, the Target URL entered by the operator is directly authorized as scope. Reviewing `$VA_RUN_DIR/scope.yml` is completely optional (used only if strict multi-host enterprise whitelists or rate constraints are formally required).
3. Run the pipeline:

```bash
python3 scripts/run_pipeline.py
```

For fragile network/security devices, prefer `Process Only` with existing
scanner output. If ZAP is used at all, use baseline or fragile baseline as a
secondary source, not as primary proof.

## Exports

```bash
# Export technical Excel (internal 11 sheets & customer-safe 2 sheets)
python3 scripts/export_excel.py

# Export SOC/SIEM Schema v1 JSON
python3 scripts/export_json_soc.py

# Generate interactive DVAS HTML report from OpenVAS XML
python3 scripts/generate_html_report.py "$VA_RUN_DIR/raw/report.xml" -o "$VA_RUN_DIR/reports/internal/dvas_security_report.html"
```

Exporters recalculate risk in memory so reports do not claim stale
`verification_status`/`risk_reason` combinations.

## Go/No-Go

Do not run active scans if:

- target URL or authorization is unclear;
- the target is a fragile network/security device requiring passive analysis only;
- the run contains customer secrets that are not allowed on the current host.
