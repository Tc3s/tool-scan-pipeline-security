import pandas as pd
import os
import sys

# ============== CẤU HÌNH ĐƯỜNG DẪN ĐỘNG ==============
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

# Input: Lấy trực tiếp từ kết quả mapping
INPUT_FILE = os.path.join(DATA_DIR, 'output', 'vuln_attack_mapped.csv')
# Output: File này sẽ được dùng để xuất Excel
OUTPUT_FILE = os.path.join(DATA_DIR, 'output', 'vuln_attack_enriched.csv')

# --- CẤU HÌNH TRỌNG SỐ (Mặc định nếu không có file config) ---
# Thang điểm 10
RISK_WEIGHTS = {
    'Critical': 10,
    'High': 8,
    'Medium': 5,
    'Low': 2,
    'Informational': 0,
    'Info': 0,
    'Log': 0,
    'Unknown': 0
}

def normalize_severity(val):
    """Chuẩn hóa giá trị severity về dạng chuẩn (Title Case)"""
    if pd.isna(val):
        return 'Unknown'
    s = str(val).strip().title() # ví dụ: "high " -> "High"
    # Map một số từ khóa lạ về chuẩn
    if s in ['Crit', 'Sever']: return 'Critical'
    if s in ['Mod', 'Moderate']: return 'Medium'
    return s

# === NEW RISK WEIGHTS (0-100 scale) ===
RISK_WEIGHTS_EXTENDED = {
    'Critical': 90,
    'High': 70,
    'Medium': 40,
    'Low': 10,
    'Informational': 0,
    'Info': 0,
    'Log': 0,
    'Unknown': 0
}

def calculate_risk_priority(severity: str, epss_score: float = 0.0, is_weaponized: bool = False) -> tuple:
    """
    Calculate risk score and priority using formula with Threat Intelligence.
    
    Formula:
        1. Base Score: Critical=90, High=70, Medium=40, Low=10
        2. EPSS Addon: epss_score * 100 * 0.5 (max 50 points)
        3. Exploit Addon: +50 if is_weaponized is True
        4. Final Score: Sum capped at 100
    
    Priority Mapping:
        - 90-100: P1 (Critical Action)
        - 70-89: P2
        - 40-69: P3
        - 0-39: P4
    
    Args:
        severity: Vulnerability severity (Critical/High/Medium/Low)
        epss_score: EPSS score (0.0 to 1.0)
        is_weaponized: Whether exploit is publicly available
        
    Returns:
        Tuple of (final_score, priority)
    """
    # Normalize severity
    severity_normalized = normalize_severity(severity)
    
    # 1. Base Score
    base_score = RISK_WEIGHTS_EXTENDED.get(severity_normalized, 0)
    
    # 2. EPSS Addon (max 50 pts)
    epss_addon = min(float(epss_score) * 100 * 0.5, 50.0)
    
    # 3. Exploit Addon (+50 if weaponized)
    exploit_addon = 50 if is_weaponized else 0
    
    # 4. Final Score (capped at 100)
    final_score = min(base_score + epss_addon + exploit_addon, 100)
    
    # Priority Assignment
    if final_score >= 90:
        priority = 'P1'
    elif final_score >= 70:
        priority = 'P2'
    elif final_score >= 40:
        priority = 'P3'
    else:
        priority = 'P4'
    
    return (final_score, priority)

def get_risk_score(severity):
    """[LEGACY - kept for backward compat] Lấy điểm số thang 0-10 dựa trên severity."""
    return RISK_WEIGHTS.get(normalize_severity(severity), 0)

def assign_priority(score):
    """[LEGACY - kept for backward compat] Phân loại dựa trên thang 0-10."""
    if score >= 9: return 'P1'
    if score >= 7: return 'P1'
    if score >= 5: return 'P2'
    if score >= 1: return 'P3'
    return 'P4'

def calculate_risk():
    """Hàm chính chạy độc lập — dùng cùng engine với run_pipeline.py (thang 0-100)."""
    print(f"\n🚀 [RISK] Bắt đầu tính toán mức độ ưu tiên (V2 Engine: 0-100 scale)...")
    
    # 1. Kiểm tra Input
    if not os.path.exists(INPUT_FILE):
        print(f"❌ LỖI: Không tìm thấy file đầu vào: {INPUT_FILE}")
        print("   -> Hãy chắc chắn bạn đã chạy bước 'Map ATT&CK' thành công.")
        sys.exit(1)

    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"   -> Đã tải {len(df)} lỗ hổng.")
    except Exception as e:
        print(f"❌ LỖI: Không đọc được file CSV. Chi tiết: {e}")
        sys.exit(1)

    # 2. Kiểm tra cột Severity
    if 'severity' not in df.columns:
        if 'risk' in df.columns:
            print("   -> Phát hiện cột 'risk', đổi tên thành 'severity'.")
            df.rename(columns={'risk': 'severity'}, inplace=True)
        else:
            print("⚠️ CẢNH BÁO: Không tìm thấy cột 'severity'. Gán mặc định là 'Unknown'.")
            df['severity'] = 'Unknown'

    # 3. Tính toán — dùng hàm calculate_risk_priority() (thang 0-100, có EPSS + Weaponized)
    def _apply_scoring(row):
        severity  = row.get('severity', 'Unknown')
        epss      = float(row['epss_score']) if 'epss_score' in row and pd.notna(row.get('epss_score')) else 0.0
        weaponized = str(row.get('exploit_available', 'False')).lower() == 'true' if 'exploit_available' in row else False
        score, priority = calculate_risk_priority(severity, epss, weaponized)
        return pd.Series({'risk_score': round(score, 1), 'priority': priority})

    df[['risk_score', 'priority']] = df.apply(_apply_scoring, axis=1)

    # 4. Sắp xếp lại dữ liệu (Ưu tiên cao lên đầu)
    df['_sort_p'] = df['priority'].str.extract(r'(\d+)').astype(int)
    df.sort_values(by=['_sort_p', 'risk_score'], ascending=[True, False], inplace=True)
    df.drop(columns=['_sort_p'], inplace=True)

    # 5. Lưu Output
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    cols = list(df.columns)
    priority_cols = ['priority', 'risk_score', 'severity', 'finding_name', 'scanner']
    new_order = [c for c in priority_cols if c in cols] + [c for c in cols if c not in priority_cols]
    df = df[new_order]
    df.to_csv(OUTPUT_FILE, index=False)
    
    # 6. Báo cáo nhanh
    print(f"✅ [RISK] Hoàn tất! Kết quả lưu tại: {OUTPUT_FILE}")
    print("📊 Thống kê nhanh:")
    print(df['priority'].value_counts().sort_index().to_string())

if __name__ == "__main__":
    calculate_risk()
