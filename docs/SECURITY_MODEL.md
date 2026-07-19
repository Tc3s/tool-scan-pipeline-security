# Security Model

The verifier is a production-safe presence verifier. It is not an exploitation
framework.

## Trust Boundaries

- Scanner output is untrusted input.
- AI-generated verifier code is untrusted runtime data until it passes policy
  validation, dry-run, approval hash binding, and result validation.
- Generated verifier code must live under `$VA_RUN_DIR/generated/`.
- Generated verifier code must not update the queue CSV directly.
- Exploit intelligence is CVE-level context only.
- Target-level proof exists only when `verification_status` is `REPRODUCED` or
  `CONFIRMED_PRESENT`.

## Enforcement Layers

1. `docs/VERIFY.md` defines the verifier contract.
2. `policy_validator.py` blocks obvious unsafe generated-code patterns and
   missing CLI contract options.
3. `verifier_lifecycle.py dry-run` compiles the verifier, runs policy checks,
   and requires a non-network `verification_plan.json`.
4. `approval_manifest.json` binds target, verifier hash, queue hash, scope hash,
   and AI context hashes.
5. `verifier_lifecycle.py run` rejects stale approvals before live target
   contact.
6. The generated verifier writes `verification_results.jsonl`.
7. `apply_verification_results.py` validates status/evidence schema and updates
   only verification/risk fields.

## Disallowed Live Behavior

- brute force, default credential login attempts, or credential stuffing;
- RCE, deserialization, command execution, SSRF, file-read, upload, write,
  delete, create-account, or destructive fuzzing;
- redirects or requests outside configured scope;
- leaking raw cookies, passwords, tokens, or Authorization headers;
- SQLMap/nmap modes that enumerate, exploit, dump, or scan outside exact scope.

## Fragile Devices

Network devices and security appliances should be treated as fragile by
default. ZAP baseline can be used as secondary scanner evidence only. Do not run
ZAP full scan, AJAX spider, nuclei intrusive templates, SQLMap, or broad nmap
against those targets without a separate written approval and maintenance
window.

## Runtime Data

Runtime data is sensitive even when customer-safe redaction is enabled.
Customer-safe means reduced exposure, not public-safe. Run-specific handoff,
workthrough, reports, AI context, generated verifiers, and approvals should stay
under ignored runtime directories.
