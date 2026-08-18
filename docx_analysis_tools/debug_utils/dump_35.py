#!/usr/bin/env python3
import pandas as pd
import re

old_df = pd.read_csv('runs/run_20260810_140029/output/vuln_raw.csv')
new_df = pd.read_csv('runs/run_20260810_192535/output/vuln_attack_enriched.csv')

old_df = old_df[~old_df['severity'].astype(str).str.upper().isin(['INFORMATIONAL', 'INFO'])].copy()
new_df = new_df[~new_df['severity'].astype(str).str.upper().isin(['INFORMATIONAL', 'INFO'])].copy()

laptop = old_df[old_df['location'].astype(str).str.contains('192.168.95.135', na=False) | old_df['asset'].astype(str).str.contains('192.168.95.135', na=False)]
web = new_df[new_df['location'].astype(str).str.contains('192.168.95.138', na=False) | new_df['asset'].astype(str).str.contains('192.168.95.138', na=False)]

print("=== ALL LAPTOP FINDINGS ===")
for idx, r in laptop.reset_index().iterrows():
    print(f"L{idx+1}. [{r.get('severity')}] {r.get('finding_name')}")

print("\n=== ALL WEB SERVER FINDINGS ===")
for idx, r in web.reset_index().iterrows():
    print(f"W{idx+1}. [{r.get('severity')}] {r.get('finding_name')}")
