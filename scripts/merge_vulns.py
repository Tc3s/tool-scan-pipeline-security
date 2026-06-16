#!/usr/bin/env python3
import pandas as pd
import os

# ============== CẤU HÌNH ĐƯỜNG DẪN ĐỘNG ==============
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

zap_file = os.path.join(DATA_DIR, "normalized", "zap_findings.csv")
openvas_file = os.path.join(DATA_DIR, "normalized", "openvas_findings.csv")
output_dir = os.path.join(DATA_DIR, "output")
output_file = os.path.join(output_dir, "vuln_raw.csv")

# Read ZAP (bắt buộc)
if not os.path.exists(zap_file):
    print(f"❌ Không tìm thấy {zap_file}")
    import sys; sys.exit(1)

zap = pd.read_csv(zap_file)
print(f"ZAP findings: {len(zap)}")

# Read OpenVAS (tuỳ chọn)
frames = [zap]
if os.path.exists(openvas_file):
    openvas = pd.read_csv(openvas_file)
    print(f"OpenVAS findings: {len(openvas)}")
    frames.append(openvas)
else:
    print("⚠️  OpenVAS findings not found — merging ZAP data only.")

# Concat
combined = pd.concat(frames, ignore_index=True)

# Dedupe by key columns
combined.drop_duplicates(
    subset=['scanner', 'asset', 'url_or_port', 'finding_name'],
    keep='first',
    inplace=True
)

# Save
os.makedirs(output_dir, exist_ok=True)
combined.to_csv(output_file, index=False)
print(f"✅ Merged → {len(combined)} unique findings in {os.path.basename(output_file)}")
print(f"✅ Merged → {len(combined)} unique findings in vuln_raw.csv")
