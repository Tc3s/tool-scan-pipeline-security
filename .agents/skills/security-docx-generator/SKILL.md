---
name: security-docx-generator
description: >-
  Standardized runbook and skill for generating flawless, corporate-grade cybersecurity vulnerability assessment DOCX reports.
  Enforces mandatory subagent debate, empirical verification, and triple cross-checking before document delivery.
---

# Security Assessment DOCX Report Generator Skill

This skill provides step-by-step instructions, rules, and helper scripts for generating professional, fault-tolerant cybersecurity vulnerability report documents (`.docx`) matching corporate template standards (e.g. `MAU REPORT.docx`).

--------------------------------------------------------------------------------

## Mandatory Core Principle: Debate & Cross-Check Protocol

BEFORE making any structural decision or declaring a document complete, the agent MUST:
1. **Debate Proposals & Edge Cases**: Challenge assumptions, inspect error logs, and invoke subagents to debate layout, pagination, or localization edge cases.
2. **Perform 3-Way Cross-Checking**: Verify data consistency 1:1 across:
   - Raw scan CSV output files (`runs/run_.../output/*.csv`).
   - Persistent JSON Knowledge Base (`docx_analysis_tools/full_vulnerability_knowledge_base.json`).
   - Template blueprint & formatting requirements (`MAU REPORT.docx`).
3. **Enforce 16-Assertion Automated Validation**: Run `validate_report_perfection.py` and ensure 100% PASS (16/16 assertions).

--------------------------------------------------------------------------------

## Key Technical Rules & Mandatory Guidelines

### 1. Complete Body XML Purging (Critical XML Rule)
- **Problem**: Calling standard python-docx paragraph/table removal (`doc.paragraphs.remove()`) leaves hidden Structured Document Tag (`w:sdt`) containers in Word XML, causing old cached Table of Contents (TOC) entries or residual template text to leak into generated reports.
- **Rule**: You MUST purge the document body XML directly, removing all children of `w:body` EXCEPT `sectPr` (which preserves page margins, section properties, headers, and footers):
```python
for child in list(doc._element.body):
    if not child.tag.endswith('sectPr'):
        doc._element.body.remove(child)
```

### 2. Matplotlib Chart Rendering & Padding (Clipping Prevention Rule)
- **Problem**: Standard matplotlib figures often clip top titles or side axis labels when embedded into Word documents.
- **Rule**: Always match canvas dimensions to printable area width (6.2 in) and render charts with explicit padding:
```python
fig, ax = plt.subplots(figsize=(8.5, 4.5))
ax.set_title("BIỂU ĐỒ ...", fontweight='bold', fontsize=12, pad=15)
plt.savefig(chart_path, dpi=300, bbox_inches='tight', pad_inches=0.3)
```

### 3. Chart Placement & Section Separation Rule
- Place **Chart 1** (Laptop Vulnerability Distribution) directly inside **Section 2.1** under heading `2.1. KẾT QUẢ DÒ QUÉT LỖ HỔNG BẢO MẬT MÁY TÍNH XÁCH TAY`.
- Place **Chart 2** (Web Server Vulnerability Distribution) directly inside **Section 2.2** under heading `2.2. KẾT QUẢ DÒ QUÉT LỖ HỔNG BẢO MẬT WEB SERVER`.
- Place the Delta Comparison Table & Risk Narrative inside **Section 2.3**.

### 4. Severity Localization & Filtering Rule
- **Filter Out Noise**: Completely exclude all `INFORMATIONAL` / `INFO` level findings.
- **Localization (100% Vietnamese)**:
  - `CRITICAL` $\rightarrow$ **NGHIÊM TRỌNG** (Bold Red `#FF0000`)
  - `HIGH` $\rightarrow$ **CAO** (Bold Dark Red `#C00000`)
  - `MEDIUM` $\rightarrow$ **TRUNG BÌNH** (Bold Orange `#ED7D31`)
  - `LOW` $\rightarrow$ **THẤP** (Bold Blue `#4472C4`)
- **Zero English Severity Strings**: Ensure no English severity terms remain in text or tables.

### 5. Evidence & Callout Box Formatting
- Title evidence sections as **"Bằng chứng:"**.
- Wrap evidence content inside a single-cell 1x1 table (`Table Grid` style) with soft background shading (`#F9F9F9`).
- Translate and distill all descriptions, evidence, and recommendations into concise, articulate, professional Vietnamese without raw HTML tags (`<p>`).

### 6. Strict Table Pagination & Layout Controls
- **Row Break Prevention (`w:cantSplit`)**: Attach `<w:cantSplit/>` to `w:trPr` of ALL table rows to prevent rows from breaking mid-cell across page splits.
- **Header Repeat (`w:tblHeader`)**: Attach `<w:tblHeader/>` to `w:trPr` of row 0 on all data tables so headers repeat automatically on subsequent pages.
- **Orphan Prevention (`w:keepNext`)**: Always set `paragraph_format.keep_with_next = True` on all Headings (Heading 1, 2, 3).

### 7. Persistent Knowledge Base Requirement
- BEFORE generating the document, parse and export all findings, translations, and metadata into a persistent JSON Knowledge Base file (`docx_analysis_tools/full_vulnerability_knowledge_base.json`) so data is preserved across sessions.

### 8. Dual Table of Contents (TOC) Rule
- Include both a structured 2-column visual table (`NỘI DUNG CẤU TRÚC BÁO CÁO` | `TRANG`) and a native Word field (`TOC \o "1-3" \h \z \u`).

--------------------------------------------------------------------------------

## Automated Workflow Steps

1. **Step 1: Data Extraction & Persistence**
   Run the persistent database generator script to parse raw scan outputs into JSON:
   `python3 docx_analysis_tools/persist_knowledge_base.py`

2. **Step 2: Master Document Generation**
   Run the perfection generator script applying all 8 technical rules:
   `python3 docx_analysis_tools/build_perfection_v6.py`

3. **Step 3: 16-Assertion Automated Quality Validation & Cross-Checking**
   Execute the strict automated audit suite to verify 100% compliance:
   `python3 docx_analysis_tools/validate_report_perfection.py Bao_Cao_An_Toan_Thong_Tin_2026.docx`
