#!/usr/bin/env python3
import pandas as pd

# Read both CSVs
zap = pd.read_csv('data/normalized/zap_findings.csv')
openvas = pd.read_csv('data/normalized/openvas_findings.csv')

print(f"ZAP findings: {len(zap)}")
print(f"OpenVAS findings: {len(openvas)}")

# Concat
combined = pd.concat([zap, openvas], ignore_index=True)

# Dedupe by key columns
combined.drop_duplicates(
    subset=['scanner', 'asset', 'url_or_port', 'finding_name'],
    keep='first',
    inplace=True
)

# Save
combined.to_csv('data/output/vuln_raw.csv', index=False)
print(f"✅ Merged → {len(combined)} unique findings in vuln_raw.csv")
