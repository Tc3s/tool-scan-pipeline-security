#!/usr/bin/env python3
import docx

doc = docx.Document('MAU REPORT.docx')

print("=== TABLES IN SECTION 2 ===")
for idx, table in enumerate(doc.tables[5:12]):
    print(f"\n--- Table {idx+6} ({len(table.rows)} rows x {len(table.columns)} cols) ---")
    for r_idx, row in enumerate(table.rows):
        row_str = " | ".join([cell.text.replace('\n', ' ') for cell in row.cells])
        print(f"Row {r_idx}: {row_str}")
