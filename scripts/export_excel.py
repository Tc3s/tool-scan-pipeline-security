import pandas as pd
import os
import sys

INPUT_FILE = 'data/output/vuln_attack_enriched.csv'
QUEUE_FILE = 'data/output/vuln_validation_queue.csv'
OUTPUT_FILE = 'vuln_attack_report.xlsx'

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

    # Sort dữ liệu
    if 'agent_status' in df.columns:
        df['sort_helper'] = df['agent_status'].astype(str).apply(lambda x: 0 if 'VERIFIED' in x else 1)
        sort_cols = ['sort_helper']
        asc_order = [True]
        
        if 'priority' in df.columns:
            sort_cols.append('priority')
            asc_order.append(True)
        if 'risk_score' in df.columns:
            sort_cols.append('risk_score')
            asc_order.append(False)
            
        df.sort_values(by=sort_cols, ascending=asc_order, inplace=True)
        df.drop(columns=['sort_helper'], inplace=True)

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
    fmt_verified = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'bold': True, 'align': 'center', 'border': 1})
    fmt_cve = workbook.add_format({'font_color': '#0000EE', 'underline': True}) # Màu xanh link cho CVE

    # --- FORMATTING ---
    for i, col in enumerate(df.columns):
        worksheet.write(0, i, col, fmt_header)
        
        # Độ rộng cột thông minh
        col_lower = col.lower()
        if 'description' in col_lower or 'evidence' in col_lower or 'solution' in col_lower:
            width = 50 # Cột nội dung dài thì cho rộng
        elif 'cve' in col_lower or 'cwe' in col_lower:
            width = 15 # CVE, CWE hẹp vừa phải
        elif 'priority' in col_lower or 'score' in col_lower:
            width = 10 # Cột điểm số hẹp
        else:
            width = 25 # Mặc định
            
        worksheet.set_column(i, i, width)

    worksheet.freeze_panes(1, 0)
    worksheet.autofilter(0, 0, max_row, max_col - 1)

    # --- CONDITIONAL FORMATTING ---
    col_idx = {name: i for i, name in enumerate(df.columns)}
    
    def apply_rule(col_name, rules):
        if col_name in col_idx:
            c = get_excel_col_name(col_idx[col_name])
            rng = f"{c}2:{c}{max_row+1}"
            for r in rules: worksheet.conditional_format(rng, r)

    apply_rule('priority', [
        {'type': 'text', 'criteria': 'containing', 'value': 'P1', 'format': fmt_critical},
        {'type': 'text', 'criteria': 'containing', 'value': 'P2', 'format': fmt_high},
        {'type': 'text', 'criteria': 'containing', 'value': 'P3', 'format': fmt_medium}
    ])
    
    apply_rule('agent_status', [
        {'type': 'text', 'criteria': 'containing', 'value': 'VERIFIED', 'format': fmt_verified}
    ])

    writer.close()
    print(f"✅ [EXCEL] Báo cáo Full Data đã lưu: {OUTPUT_FILE}")

if __name__ == "__main__":
    export_clean_report()
