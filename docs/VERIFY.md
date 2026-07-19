# AI Verification Contract

This document is the stable handoff for AI agents that generate a per-run
presence verifier. Read it before writing code.

## Trust Boundary

The generated verifier is a runtime artifact, not trusted source code. It must
not be committed as a stable project file and must not update the validation CSV
directly.

The stable pipeline owns:

- policy validation;
- dry-run approval manifest creation;
- approval hash binding;
- applying verification results to the queue;
- recalculating risk;
- exporting customer/internal reports.

## Runtime Paths

Use the paths passed by CLI flags. Do not hardcode project paths, target IPs, or
customer paths.

Default per-run paths:

- verifier: `$VA_RUN_DIR/generated/verify_vulns.py`
- scope: `$VA_RUN_DIR/scope.yml`
- queue: `$VA_RUN_DIR/output/vuln_validation_queue.csv`
- AI manifest: `$VA_RUN_DIR/ai_context/internal/manifest.json`
- finding context: `$VA_RUN_DIR/ai_context/internal/verification_context.jsonl`
- ZAP instances: `$VA_RUN_DIR/ai_context/internal/zap_instances_compact.jsonl`
- dry-run plan: `$VA_RUN_DIR/verification/verification_plan.json`
- live results: `$VA_RUN_DIR/verification/verification_results.jsonl`
- approval: `$VA_RUN_DIR/approval_manifest.json`

If `VA_RUN_DIR` is unset, the development fallback is `data/`. Production runs
should set `VA_RUN_DIR`.

## Required CLI

The generated verifier must accept this CLI:

```bash
python3 "$VA_RUN_DIR/generated/verify_vulns.py" TARGET \
  --mode BLACKBOX_UNAUTHENTICATED \
  --context-file "$VA_RUN_DIR/ai_context/internal/verification_context.jsonl" \
  --zap-context-file "$VA_RUN_DIR/ai_context/internal/zap_instances_compact.jsonl" \
  --scope-file "$VA_RUN_DIR/scope.yml" \
  --dry-run \
  --plan-file "$VA_RUN_DIR/verification/verification_plan.json"
```

```bash
python3 "$VA_RUN_DIR/generated/verify_vulns.py" TARGET \
  --mode BLACKBOX_UNAUTHENTICATED \
  --context-file "$VA_RUN_DIR/ai_context/internal/verification_context.jsonl" \
  --zap-context-file "$VA_RUN_DIR/ai_context/internal/zap_instances_compact.jsonl" \
  --scope-file "$VA_RUN_DIR/scope.yml" \
  --approval-file "$VA_RUN_DIR/approval_manifest.json" \
  --results-file "$VA_RUN_DIR/verification/verification_results.jsonl"
```

`--mode` is either `BLACKBOX_UNAUTHENTICATED` or `GREYBOX_AUTHENTICATED`.

## Dry-Run Contract

Dry-run must not contact the target and must not mutate the queue.

Dry-run writes one JSON object to `--plan-file`:

```json
{
  "schema_version": "generated-verifier-plan-1.0",
  "generated_at": "2026-07-19T00:00:00+00:00",
  "target": "https://target.example",
  "mode": "BLACKBOX_UNAUTHENTICATED",
  "planned_total": 12,
  "planned_status_counts": {
    "CHECKED_NOT_REPRODUCED": 4,
    "CONFIRMED_PRESENT": 2,
    "NEEDS_MANUAL_REVIEW": 6
  },
  "planned_methods": ["http_header_check", "tls_config_check"],
  "manual_review_ids": ["F0004-abcd1234ef"],
  "unsafe_skipped_ids": ["F0008-1234abcdef"],
  "notes": ["No network requests were made during dry-run."]
}
```

The stable wrapper creates `approval_manifest.json`; generated code must not
self-approve.

## Live Result Contract

Live mode writes JSONL to `--results-file`. Each line is one result object:

```json
{"schema_version":"verification-result-1.0","finding_id":"F0001-abcdef1234","status":"CONFIRMED_PRESENT","method":"http_header_check","evidence":"GET https://target.example observed missing X-Frame-Options on same URL reported by scanner.","confidence":"HIGH","safe_mode":true,"completed_at":"2026-07-19T00:00:00+00:00"}
```

Required fields:

- `finding_id`
- `status`
- `method`
- `evidence` or `error`
- `confidence`
- `safe_mode`
- `completed_at`

Allowed statuses:

- `REPRODUCED`
- `CONFIRMED_PRESENT`
- `CHECKED_NOT_REPRODUCED`
- `FALSE_POSITIVE`
- `SKIPPED_SAFE_MODE`
- `NEEDS_MANUAL_REVIEW`
- `ERROR`

Do not output `NOT_VERIFIED` as a live result. Missing rows remain
`NOT_VERIFIED`.

## Evidence Standard

Evidence must be target-specific and conservative:

- include URL/host/port;
- include method/tool;
- include observed condition;
- explain why it proves, disproves, or cannot safely prove the finding;
- redact cookies, tokens, passwords, Authorization headers, API keys, and
  customer secrets;
- keep evidence under 800 characters.

`REPRODUCED` and `CONFIRMED_PRESENT` require direct target-specific evidence and
must not be based only on public exploit intelligence.

`FALSE_POSITIVE` requires contradiction evidence, such as exact fixed version,
not-applicable product, or safe check proving the scanner condition is absent.

Ambiguous cases become `NEEDS_MANUAL_REVIEW` or `SKIPPED_SAFE_MODE`.

## Production Safety

Treat all targets as production.

Allowed by default:

- exact in-scope `GET`, `HEAD`, `OPTIONS`;
- TLS configuration checks on the exact host/port;
- exact service/banner version checks on the port from the finding;
- reading scanner evidence and AI context.

Disallowed:

- brute force, default credential login, password spraying;
- RCE, SSRF, deserialization, file-read, upload, write/delete/create actions;
- DoS, fuzzing, crawling beyond scanner-listed URLs;
- cloud metadata, localhost, file/data URI, or host pivot checks;
- SQLMap unless `VA_ALLOW_SQLMAP=true` and the row has explicit approval;
- nmap ranges, unrelated ports, intrusive/vuln/exploit/dos/brute scripts;
- any request outside `scope.yml`.

Use timeout <= 10 seconds, concurrency 1, at most one retry, and back off on
429/403/5xx spikes, resets, or latency jumps. For fragile network/security
devices, prefer `SKIPPED_SAFE_MODE` and scanner evidence over active probes.

## Stable Wrapper Commands

The operator or pipeline runs these commands after the generated verifier is
created:

```bash
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" prepare https://target.example
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" dry-run https://target.example
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" approve https://target.example --operator analyst
python3 scripts/verifier_lifecycle.py --mode BLACKBOX --verifier-file "$VA_RUN_DIR/generated/verify_vulns.py" run https://target.example
```

The wrapper rejects the run if verifier hash, target, queue hash, scope hash, or
AI context hashes changed after dry-run.

Wrapper timeouts:

- dry-run: `VA_VERIFIER_DRY_RUN_TIMEOUT`, default 120 seconds;
- live run: `VA_VERIFIER_LIVE_TIMEOUT`, default 3600 seconds.
