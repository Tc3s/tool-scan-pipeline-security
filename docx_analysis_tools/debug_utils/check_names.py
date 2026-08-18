#!/usr/bin/env python3
import pandas as pd

df1 = pd.read_csv('runs/run_20260810_140029/output/vuln_raw.csv')
df2 = pd.read_csv('runs/run_20260810_192535/output/vuln_attack_enriched.csv')

laptop_findings = df1[df1['location'].astype(str).str.contains('192.168.95.135', na=False) | df1['asset'].astype(str).str.contains('192.168.95.135', na=False)]['finding_name'].tolist()
web_findings = df2[df2['location'].astype(str).str.contains('192.168.95.138', na=False) | df2['asset'].astype(str).str.contains('192.168.95.138', na=False)]['finding_name'].tolist()

print("=== LAPTOP FINDINGS IN RUN 140029 ===")
for f in laptop_findings:
    print(f" - {f}")

print("\n=== WEB SERVER FINDINGS IN RUN 192535 (First 10) ===")
for f in web_findings[:10]:
    print(f" - {f}")
