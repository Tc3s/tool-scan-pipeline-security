import pandas as pd
import os
import sys

# ============== CẤU HÌNH ĐƯỜNG DẪN ĐỘNG ==============
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
OUTPUT_DIR = os.path.join(DATA_DIR, "output")

INPUT_FILE = os.path.join(OUTPUT_DIR, 'vuln_attack_enriched.csv')
QUEUE_FILE = os.path.join(OUTPUT_DIR, 'vuln_validation_queue.csv')
OUTPUT_FILE = os.path.join(PROJECT_ROOT, 'vuln_attack_report.xlsx')

# Hàm hỗ trợ tính toán tên cột Excel (A, B, C... AA, AB...)
def get_excel_col_name(n):
    string = ""
    while n >= 0:
        string = chr(n % 26 + 65) + string
        n = n // 26 - 1
    return string

def export_clean_report():
    print("📊 [EXCEL] Đang xuất báo cáo Full Data...")

    # Ưu tiên file Queue (vì nó chứa kết quả Verify và giờ đã có Full Data)
    df = None
    if os.path.exists(QUEUE_FILE):
        try:
            df_queue = pd.read_csv(QUEUE_FILE)
            if 'agent_status' in df_queue.columns:
                print(f"   -> Sử dụng dữ liệu từ {QUEUE_FILE}")
                df = df_queue
        except: pass
    
    if df is None and os.path.exists(INPUT_FILE):
        df = pd.read_csv(INPUT_FILE)

    if df is None:
        print("❌ LỖI: Không có dữ liệu.")
        sys.exit(1)

    # --- SỬA LỖI QUAN TRỌNG: XỬ LÝ DỮ LIỆU TRỐNG ---
    if 'agent_status' in df.columns:
        # Chuyển đổi NaN thành chuỗi rỗng để tránh lỗi TypeError
        df['agent_status'] = df['agent_status'].fillna('WAITING')
        
        # Logic sắp xếp mới: Tương thích với Prompt V4.9
        # 0: Đã bắn thủng (REPRODUCED)
        # 1: Đã xác nhận (CONFIRMED / VERIFIED)
        # 2: Đã kiểm tra (CHECKED)
        # 3: Còn lại
        def get_sort_val(status):
            s = str(status).upper()
            if 'REPRODUCED' in s: return 0
            if 'CONFIRMED' in s or 'VERIFIED' in s: return 1
            if 'CHECKED' in s: return 2
            return 3

        df['sort_helper'] = df['agent_status'].apply(get_sort_val)
        
        sort_cols = ['sort_helper']
        asc_order = [True]
        
        if 'priority' in df.columns:
            sort_cols.append('priority')
            asc_order.append(True) # P1 trước P2
        if 'risk_score' in df.columns:
            sort_cols.append('risk_score')
            asc_order.append(False) # Điểm cao trước
            
        df.sort_values(by=sort_cols, ascending=asc_order, inplace=True)
        df.drop(columns=['sort_helper'], inplace=True)

    # Khởi tạo Excel Writer
    writer = pd.ExcelWriter(OUTPUT_FILE, engine='xlsxwriter')
    df.to_excel(writer, index=False, sheet_name='Security Report')

    workbook  = writer.book
    worksheet = writer.sheets['Security Report']
    (max_row, max_col) = df.shape

    # --- STYLES ---
    fmt_header = workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#1F4E78', 'border': 1, 'align': 'center', 'valign': 'vcenter'})
    fmt_critical = workbook.add_format({'bg_color': '#C00000', 'font_color': 'white', 'bold': True, 'align': 'center'})
    fmt_high = workbook.add_format({'bg_color': '#FFC000', 'font_color': 'black', 'align': 'center'})
    fmt_medium = workbook.add_format({'bg_color': '#FFFFCC', 'font_color': 'black', 'align': 'center'})
    
    # Style cho trạng thái Verified/Confirmed/Reproduced
    fmt_verified = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'bold': True, 'align': 'center', 'border': 1})
    
    fmt_cve = workbook.add_format({'font_color': '#0000EE', 'underline': True}) # Màu xanh link cho CVE

    # --- FORMATTING ---
    for i, col in enumerate(df.columns):
        worksheet.write(0, i, col, fmt_header)
        
        # Độ rộng cột thông minh
        col_lower = col.lower()
        width = 25 # Mặc định
        
        if 'description' in col_lower or 'evidence' in col_lower or 'solution' in col_lower:
            width = 50 
        elif 'cve' in col_lower or 'cwe' in col_lower:
            width = 15 
        elif 'priority' in col_lower or 'score' in col_lower:
            width = 10 
            
        worksheet.set_column(i, i, width)

    worksheet.freeze_panes(1, 0)
    # worksheet.autofilter(0, 0, max_row, max_col - 1) # Có thể bật lại nếu muốn filter

    # --- CONDITIONAL FORMATTING ---
    # Helper để tìm index cột
    col_idx = {name: i for i, name in enumerate(df.columns)}
    
    def apply_rule(col_name, rules):
        if col_name in col_idx:
            # Chuyển index số thành chữ (A, B, C...)
            c_letter = ""
            n = col_idx[col_name]
            while n >= 0:
                c_letter = chr(n % 26 + 65) + c_letter
                n = n // 26 - 1
            
            # Range: Từ dòng 2 đến hết
            rng = f"{c_letter}2:{c_letter}{max_row+1}"
            for r in rules: worksheet.conditional_format(rng, r)

    # Tô màu cột Priority
    apply_rule('priority', [
        {'type': 'text', 'criteria': 'containing', 'value': 'P1', 'format': fmt_critical},
        {'type': 'text', 'criteria': 'containing', 'value': 'P2', 'format': fmt_high},
        {'type': 'text', 'criteria': 'containing', 'value': 'P3', 'format': fmt_medium}
    ])
    
    # Tô màu cột Agent Status (Cập nhật cho V4.9)
    apply_rule('agent_status', [
        {'type': 'text', 'criteria': 'containing', 'value': 'VERIFIED', 'format': fmt_verified},
        {'type': 'text', 'criteria': 'containing', 'value': 'CONFIRMED', 'format': fmt_verified},
        {'type': 'text', 'criteria': 'containing', 'value': 'REPRODUCED', 'format': fmt_verified}
    ])

    writer.close()
    print(f"✅ [EXCEL] Báo cáo Full Data đã lưu: {OUTPUT_FILE}")

if __name__ == "__main__":
    export_clean_report()
