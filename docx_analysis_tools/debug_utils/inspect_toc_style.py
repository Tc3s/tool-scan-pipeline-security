#!/usr/bin/env python3
import docx

doc = docx.Document('MAU REPORT.docx')

print("=== CHECKING TOC PAGE FORMATTING IN MAU REPORT.docx ===")
for p_idx, p in enumerate(doc.paragraphs[:35]):
    print(f"P {p_idx} ({p.style.name}): {p.text}")
