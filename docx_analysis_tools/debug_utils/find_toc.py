#!/usr/bin/env python3
import docx

doc = docx.Document('MAU REPORT.docx')

print("=== SEARCHING FOR TOC / HARDCODED TOC IN MAU REPORT.docx ===")
for p_idx, p in enumerate(doc.paragraphs[:50]):
    if "SQLITE" in p.text or "MỤC LỤC" in p.text.upper() or "3.1." in p.text:
        print(f"P {p_idx} ({p.style.name}): {p.text}")
