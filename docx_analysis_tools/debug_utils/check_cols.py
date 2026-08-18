#!/usr/bin/env python3
import pandas as pd

def check_cols(path):
    df = pd.read_csv(path)
    print(f"\nColumns for {path}:")
    print(df.columns.tolist())

check_cols('runs/run_20260810_140029/output/vuln_raw.csv')
check_cols('runs/run_20260810_192535/output/vuln_attack_enriched.csv')
