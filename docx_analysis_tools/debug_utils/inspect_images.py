#!/usr/bin/env python3
import docx

doc = docx.Document('MAU REPORT.docx')

print("=== IMAGES / DRAWINGS IN DOCX ===")
for p_idx, p in enumerate(doc.paragraphs):
    if len(p._element.xpath('.//*[local-name()="drawing" or local-name()="shape"]')) > 0:
        print(f"Paragraph {p_idx} (Heading/Text context: '{p.text[:60]}'): Has Drawing/Shape")
