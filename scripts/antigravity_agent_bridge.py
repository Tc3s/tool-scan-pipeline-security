import pandas as pd
import os
import sys

# Input: File đã được làm giàu dữ liệu (có Risk, Mapping...)
INPUT_FILE = 'data/output/vuln_attack_enriched.csv'
# Output: File hàng đợi cho Agent xử lý
OUTPUT_FILE = 'data/output/vuln_validation_queue.csv'

def create_bridge_queue():
    print("🌉 [BRIDGE] Đang tạo hàng đợi kiểm tra (Full Columns)...")
    
    if not os.path.exists(INPUT_FILE):
        print(f"❌ LỖI: Không tìm thấy {INPUT_FILE}. Hãy chạy bước Processing trước.")
        sys.exit(1)

    try:
        df = pd.read_csv(INPUT_FILE)
        
        # 1. Giữ nguyên TOÀN BỘ cột dữ liệu gốc (CVE, CWE, Priority, Risk...)
        # Không thực hiện lệnh df = df[...] để lọc cột nữa.
        
        # 2. Thêm các cột dành cho Agent (nếu chưa có)
        if 'agent_status' not in df.columns:
            df['agent_status'] = 'WAITING'
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
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"✅ [BRIDGE] Đã tạo file hàng đợi: {OUTPUT_FILE}")
        print(f"   -> Số lượng: {len(df)} lỗ hổng.")
        print(f"   -> Dữ liệu: Đầy đủ CVE, CWE, Priority...")
        
    except Exception as e:
        print(f"❌ LỖI BRIDGE: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    create_bridge_queue()
