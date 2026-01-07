# Task 4: ATT&CK Vulnerability Management Pipeline

## Overview
PoC pipeline to normalize vulnerability findings from ZAP/OpenVAS, map to MITRE ATT&CK techniques, calculate risk scores, and prioritize remediation (P1-P4).

## Architecture
OWASP ZAP → parse_zap.py → normalized CSV
↓
OpenVAS → parse_openvas.py → merge → vuln_raw.csv
↓
apply_attack_mapping.py (rules-based)
↓
vuln_attack_mapped.csv
↓
calculate_risk_priority.py
↓
vuln_attack_enriched.csv → Excel

text

## Quick Start

### 1. Scan Target
Start DVWA target
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa

Run ZAP scan
docker run --rm -v $(pwd)/data/raw:/zap/wrk/:rw
ghcr.io/zaproxy/zaproxy:stable
zap-baseline.py -t http://172.17.0.1:8080
-J zap_report.json -r zap_report.html

text

### 2. Run Pipeline
source venv/bin/activate

Parse ZAP report
python scripts/parse_zap.py

Apply ATT&CK mapping
python scripts/apply_attack_mapping.py

Calculate risk + priority
python scripts/calculate_risk_priority.py

Export Excel
python scripts/export_excel.py

View stats
python scripts/show_stats.py

text

## Output Files

| File | Description |
|------|-------------|
| `data/output/vuln_raw.csv` | Normalized findings from scanners |
| `data/output/vuln_attack_enriched.csv` | Full pipeline output with ATT&CK + risk |
| `data/output/vuln_attack_report.xlsx` | Excel with pivot tables |

## CSV Schema

### vuln_attack_enriched.csv columns:
- **scanner**: ZAP / OpenVAS
- **finding_name**: Vulnerability title
- **severity**: Critical / High / Medium / Low / Informational
- **cwe / cve**: Weakness / vulnerability IDs
- **attack_tactic**: MITRE ATT&CK tactic (e.g., Initial Access)
- **attack_technique_id**: Technique ID (e.g., T1189)
- **attack_technique_name**: Technique name
- **attack_confidence**: 0.0-1.0 (rule confidence)
- **risk_score**: 0-100 calculated score
- **priority**: P1 / P2 / P3 / P4
- **reason**: 1-sentence explanation

## Configuration

### mapping/attack_mapping_rules.yml
- Pattern-based rules: finding_name / CWE / CVE → Technique
- Add new rules to increase coverage

### mapping/risk_weights.yml
- Tactic impact weights (Initial Access = 1.0, Discovery = 0.6)
- Severity weights (Critical = 1.0, Low = 0.3)
- Priority thresholds (P1 >= 75, P2 >= 60, P3 >= 40)

## Metrics

- **Coverage**: % of findings mapped to ATT&CK technique
- **Priority distribution**: P1-P4 counts
- **Top techniques**: Most common attack patterns

See `docs/examples.md` for sample findings.
