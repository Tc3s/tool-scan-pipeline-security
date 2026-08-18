# VA Pipeline Operations

This runbook describes the controlled operating flow. Runtime artifacts should
live outside committed source by setting `VA_RUN_DIR`.

## Runtime Layout

Recommended per-run layout:

```bash
export VA_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
export VA_RUN_DIR="$PWD/runs/$VA_RUN_ID"
```

If `VA_RUN_DIR` is not set, the development fallback is `data/`.

## Standard Flow

1. Put raw scanner inputs under `$VA_RUN_DIR/raw/`.
2. Review `$VA_RUN_DIR/scope.yml`. Production scope must have explicit
   `allowed_hosts`, schemes, ports, methods, request rate, and concurrency.
3. Run the pipeline:

```bash
python3 scripts/run_pipeline.py
```

For fragile network/security devices, prefer `Process Only` with existing
scanner output. If ZAP is used at all, use baseline or fragile baseline as a
secondary source, not as primary proof.

## AI Verifier Flow

Generated verifier code is per-run runtime data:

```bash
$VA_RUN_DIR/generated/verify_vulns.py
```

Do not commit it as stable source. Do not create `scripts/verify_vulns.py`.

Give the AI agent the prompt printed by the pipeline and require it to read:

```text
docs/VERIFY.md
```

Then run the stable lifecycle wrapper:

```bash
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" prepare https://target.example
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" dry-run https://target.example
```

Review:

```text
$VA_RUN_DIR/verification/verification_plan.json
$VA_RUN_DIR/approval_manifest.json
```

Approve only after operator review:

```bash
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" approve https://target.example --operator analyst
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" run https://target.example
```

The wrapper rejects live verification if verifier hash, target, queue hash,
scope hash, or AI context hashes changed after dry-run.

## Exports

```bash
# Export technical Excel (internal 11 sheets & customer-safe 2 sheets)
python3 scripts/export_excel.py

# Export SOC/SIEM Schema v1 JSON
python3 scripts/export_json_soc.py

# Export compact AI context JSONL
python3 scripts/export_ai_context.py

# Generate executive DOCX report & run 16-assertion quality audit
python3 docx_analysis_tools/build_perfection_report.py
python3 docx_analysis_tools/validate_report_perfection.py Bao_Cao_An_Toan_Thong_Tin_2026.docx
```

Exporters recalculate risk in memory so reports do not claim stale
`verification_status`/`risk_reason` combinations.

## Go/No-Go

Do not run live verification if:

- policy validation fails;
- dry-run planned scope is broader than expected;
- approval manifest hashes do not match the reviewed verifier/run inputs;
- target, allowed hosts, or allowed ports are unclear;
- the target is a fragile device and proof requires active payloads;
- the run contains customer secrets that are not allowed on the current host.
