import pandas as pd
import os
import sys
import subprocess
from pathlib import Path

try:
    from scripts import runtime_context as rt
except ImportError:
    import runtime_context as rt

# Input: File đã được làm giàu dữ liệu (có Risk, Mapping...)
INPUT_FILE = rt.output_dir() / 'vuln_attack_enriched.csv'
# Output: File hàng đợi cho Agent xử lý
OUTPUT_FILE = rt.output_dir() / 'vuln_validation_queue.csv'

LEGACY_AGENT_STATUSES = {
    'NO_CVE_ID',
    'NO_PUBLIC_EXPLOIT_FOUND',
    'PUBLIC_EXPLOIT_AVAILABLE',
    'EXPLOIT_TEMPLATE_AVAILABLE',
    'INTEL_CHECK_ERROR',
}


def choose_input_file():
    """Prefer the active in-memory queue if run_pipeline already saved it."""
    if OUTPUT_FILE.exists():
        if not INPUT_FILE.exists():
            return OUTPUT_FILE
        if os.path.getmtime(OUTPUT_FILE) >= os.path.getmtime(INPUT_FILE):
            return OUTPUT_FILE
    return INPUT_FILE


def normalize_agent_columns(df):
    defaults = {
        'verification_status': 'NOT_VERIFIED',
        'verification_evidence': '',
        'verification_method': '',
        'verification_command': '',
        'verification_error': '',
        'verification_confidence': '',
        'verification_started_at': '',
        'verification_completed_at': '',
        'verification_safe_mode': True,
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default

def create_bridge_queue():
    print("🌉 [BRIDGE] Đang tạo hàng đợi kiểm tra (Full Columns)...")

    source_file = choose_input_file()
    if not Path(source_file).exists():
        print(f"❌ LỖI: Không tìm thấy {source_file}. Hãy chạy bước Processing trước.")
        sys.exit(1)

    try:
        df = pd.read_csv(source_file)
        
        # 1. Giữ nguyên TOÀN BỘ cột dữ liệu gốc (CVE, CWE, Priority, Risk...)
        # Không thực hiện lệnh df = df[...] để lọc cột nữa.
        
        # 2. Thêm các cột dành cho Agent (nếu chưa có)
        normalize_agent_columns(df)

        if 'agent_status' not in df.columns:
            df['agent_status'] = 'WAITING'
        else:
            status = df['agent_status'].fillna('').astype(str).str.strip()
            verification_status = df['verification_status'].fillna('NOT_VERIFIED').astype(str).str.strip()
            should_wait = (
                status.eq('')
                | status.str.upper().isin(LEGACY_AGENT_STATUSES)
                | verification_status.str.upper().eq('NOT_VERIFIED')
            )
            df.loc[should_wait, 'agent_status'] = 'WAITING'
        if 'agent_command' not in df.columns:
            df['agent_command'] = ''
        if 'agent_evidence' not in df.columns:
            df['agent_evidence'] = ''

        # 3. Sắp xếp lại thứ tự cột cho dễ nhìn (Đưa cột quan trọng lên đầu)
        # Các cột ưu tiên hiển thị trước
        priority_cols = [
            'priority', 'risk_score', 'severity', 'finding_name', 
            'agent_status', 'agent_command', 'agent_evidence',
            'scanner', 'url_or_port', 'cve', 'cwe'
        ]
        
        # Lấy các cột còn lại
        remaining_cols = [c for c in df.columns if c not in priority_cols]
        
        # Gộp lại
        final_cols = priority_cols + remaining_cols
        # Chỉ lấy những cột thực sự tồn tại trong file
        final_cols = [c for c in final_cols if c in df.columns]
        
        df = df[final_cols]

        # 4. Lưu file
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"✅ [BRIDGE] Đã tạo file hàng đợi: {OUTPUT_FILE}")
        print(f"   -> Nguồn: {source_file}")
        print(f"   -> Số lượng: {len(df)} lỗ hổng.")
        print(f"   -> Dữ liệu: Đầy đủ CVE, CWE, Priority...")

        exporter = rt.project_root() / 'scripts' / 'export_ai_context.py'
        if exporter.exists():
            subprocess.run([sys.executable, exporter], check=False)

    except Exception as e:
        print(f"❌ LỖI BRIDGE: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    create_bridge_queue()
