# Security Model

The pipeline is a production-safe vulnerability assessment, normalization, and triage system. It is not an exploitation framework.

## Trust Boundaries

- Scanner output (ZAP JSON, OpenVAS XML) is untrusted input.
- External threat intelligence (MITRE ATT&CK, EPSS, Exploit-DB, Metasploit, Nuclei) is CVE/CWE-level context only.
- Direct Operator Authorization: The target URL provided by the operator is directly authorized as scan scope.
- Shell metacharacters are strictly validated and rejected before invoking any external scanner CLI tools.
- Air-gapped & Offline Safe: Internal reports embed 100% inline assets with zero external network phone-home requests.
- Disallowed Tools: Exploitation tools (such as `sqlmap`, `nikto`, `wpscan`) are strictly blocked by pipeline policy.

## Enforcement Layers

1. `scripts/schema_utils.py` enforces Canonical 22-column schema validation and data integrity.
2. `scripts/run_pipeline.py` validates command injection risks and enforces safe tool execution without shell expansion.
3. `scripts/merge_vulns.py` preserves disjoint CVEs and deduplicates findings losslessly.
4. `scripts/generate_html_report.py` enforces HTML entity escaping (`html.escape(quote=True)`) and URL scheme validation (`is_safe_url`) to eliminate Stored XSS.
5. Export layer segregates internal reports (11 sheets Excel, complete SOC JSON) from customer-safe deliverables (2 sheets Excel, redacted SOC JSON).

## Disallowed Live Behavior

- brute force, default credential login attempts, or credential stuffing;
- RCE, deserialization, command execution, SSRF, file-read, upload, write,
  delete, create-account, or destructive fuzzing;
- invoking disallowed exploitation tools (`sqlmap`, `nikto`, `wpscan`);
- leaking raw cookies, passwords, tokens, or Authorization headers;
- scanning outside the operator-authorized target.

## Fragile Devices

Network devices and security appliances should be treated as fragile by
default. ZAP baseline can be used as secondary scanner evidence only. Do not run
ZAP full scan, AJAX spider, nuclei intrusive templates, or broad nmap
against those targets without a separate written approval and maintenance
window.

## Runtime Data

Runtime data is sensitive even when customer-safe redaction is enabled.
Customer-safe means reduced exposure, not public-safe. Run-specific handoff,
workthrough, reports, and audit logs should stay under ignored runtime directories (`runs/`).
