import pandas as pd
import os
import sys

# --- CẤU HÌNH ĐƯỜNG DẪN ---
# Input: Lấy trực tiếp từ kết quả mapping (bỏ qua bước mock AI)
INPUT_FILE = 'data/output/vuln_attack_mapped.csv'
# Output: File này sẽ được dùng để xuất Excel
OUTPUT_FILE = 'data/output/vuln_attack_enriched.csv'

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

def get_risk_score(severity):
    """Lấy điểm số dựa trên severity đã chuẩn hóa"""
    return RISK_WEIGHTS.get(severity, 0) # Mặc định là 0 nếu không tìm thấy

def assign_priority(score):
    """Phân loại độ ưu tiên dựa trên điểm số"""
    if score >= 9: return 'P1' # Critical
    if score >= 7: return 'P1' # High
    if score >= 5: return 'P2' # Medium
    if score >= 1: return 'P3' # Low
    return 'P4' # Info/Log

def calculate_risk():
    print(f"\n🚀 [RISK] Bắt đầu tính toán mức độ ưu tiên...")
    
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
    # Một số tool scan dùng cột 'risk', số khác dùng 'severity'
    if 'severity' not in df.columns:
        if 'risk' in df.columns:
            print("   -> Phát hiện cột 'risk', đổi tên thành 'severity'.")
            df.rename(columns={'risk': 'severity'}, inplace=True)
        else:
            print("⚠️ CẢNH BÁO: Không tìm thấy cột 'severity'. Gán mặc định là 'Unknown'.")
            df['severity'] = 'Unknown'

    # 3. Tính toán
    # Chuẩn hóa text
    df['severity_normalized'] = df['severity'].apply(normalize_severity)
    
    # Tính điểm Risk Score
    df['risk_score'] = df['severity_normalized'].apply(get_risk_score)
    
    # Phân loại Priority (P1-P4)
    df['priority'] = df['risk_score'].apply(assign_priority)

    # 4. Sắp xếp lại dữ liệu (Ưu tiên cao lên đầu)
    # Sort theo: Priority (P1 < P2), sau đó đến Risk Score (Cao -> Thấp)
    df.sort_values(by=['priority', 'risk_score'], ascending=[True, False], inplace=True)

    # 5. Lưu Output
    # Đảm bảo thư mục tồn tại
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # Chọn các cột quan trọng để đưa lên đầu cho dễ nhìn
    cols = list(df.columns)
    priority_cols = ['priority', 'risk_score', 'severity', 'finding_name', 'scanner']
    
    # Tạo danh sách cột mới: Các cột ưu tiên + Các cột còn lại
    new_order = [c for c in priority_cols if c in cols] + [c for c in cols if c not in priority_cols]
    df = df[new_order]

    df.to_csv(OUTPUT_FILE, index=False)
    
    # 6. Báo cáo nhanh
    print(f"✅ [RISK] Hoàn tất! Kết quả lưu tại: {OUTPUT_FILE}")
    print("📊 Thống kê nhanh:")
    print(df['priority'].value_counts().to_string())

if __name__ == "__main__":
    calculate_risk()
