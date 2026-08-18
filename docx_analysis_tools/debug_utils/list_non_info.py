#!/usr/bin/env python3
import pandas as pd

df1 = pd.read_csv('runs/run_20260810_140029/output/vuln_raw.csv')
df2 = pd.read_csv('runs/run_20260810_192535/output/vuln_attack_enriched.csv')

# Filter non-info
laptop = df1[(df1['location'].astype(str).str.contains('192.168.95.135', na=False) | df1['asset'].astype(str).str.contains('192.168.95.135', na=False)) & (~df1['severity'].astype(str).str.upper().isin(['INFORMATIONAL', 'INFO']))]
web = df2[(df2['location'].astype(str).str.contains('192.168.95.138', na=False) | df2['asset'].astype(str).str.contains('192.168.95.138', na=False)) & (~df2['severity'].astype(str).str.upper().isin(['INFORMATIONAL', 'INFO']))]

print(f"Non-info Laptop findings count: {len(laptop)}")
print(f"Non-info Web Server findings count: {len(web)}")

print("\n--- LAPTOP FINDINGS ---")
for idx, r in laptop.reset_index().iterrows():
    print(f"{idx+1}. [{r.get('severity')}] {r.get('finding_name')}")

print("\n--- WEB SERVER FINDINGS ---")
for idx, r in web.reset_index().iterrows():
    print(f"{idx+1}. [{r.get('severity')}] {r.get('finding_name')}")
