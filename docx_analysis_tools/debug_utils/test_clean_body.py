#!/usr/bin/env python3
import docx

doc = docx.Document('MAU REPORT.docx')
print(f"Body children count before clean: {len(doc._element.body)}")

# Clear body except sectPr
for child in list(doc._element.body):
    if not child.tag.endswith('sectPr'):
        doc._element.body.remove(child)

print(f"Body children count after clean: {len(doc._element.body)}")
print("Remaining elements:", [c.tag.split('}')[-1] for c in doc._element.body])
