---
name: docx-skill
description: >-
  Unified master skill and toolkit for analyzing DOCX templates, extracting structural rules, generating corporate-grade security reports, and executing 16-assertion quality audits.
  Enforces mandatory subagent debate, empirical verification, and triple cross-checking before document delivery.
---

# Unified Master DOCX Skill (`docx-skill`)

This unified skill provides an end-to-end runbook, mandatory rules, and automated python scripts for analyzing Microsoft Word (`.docx`) templates, persisting vulnerability datasets, generating corporate-grade security reports, and running automated 16-assertion quality audits.

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

## Toolkit Architecture & Included Scripts

The `docx-skill` encapsulates 4 specialized python tools located in `docx_analysis_tools/`:

| Script Name | Purpose & Function |
| :--- | :--- |
| `analyze_docx_template.py` | Performs deep OpenXML inspection of DOCX templates (margins, headers, footers, watermarks, `tblHeader`, `cantSplit`, column widths, borders, shading, typography nuances, and numbering XML). |
| `persist_knowledge_base.py` | Extracts raw scanner data and saves a persistent, 100% localized JSON Knowledge Base (`full_vulnerability_knowledge_base.json`). |
| `build_perfection_report.py` | Master document generator enforcing XML body purging, Matplotlib chart embedding, `cantSplit`, `tblHeader`, `keep_with_next`, and font forcing. |
| `validate_report_perfection.py` | Standalone Quality Assurance Suite running 16 automated assertions against generated reports. |

--------------------------------------------------------------------------------

## Key Technical Rules & Mandatory Guidelines

### 1. Complete Body XML Purging (Critical XML Rule)
- Purge document body XML directly, removing all children of `w:body` EXCEPT `sectPr` (which preserves page margins, section properties, headers, and footers):
```python
for child in list(doc._element.body):
    if not child.tag.endswith('sectPr'):
        doc._element.body.remove(child)
```

### 2. Matplotlib Chart Rendering & Padding (Clipping Prevention Rule)
- Match figure canvas dimensions to printable area width (6.2 in) and render charts with explicit padding:
```python
fig, ax = plt.subplots(figsize=(8.5, 4.5))
ax.set_title("BIỂU ĐỒ ...", fontweight='bold', fontsize=12, pad=15)
plt.savefig(chart_path, dpi=300, bbox_inches='tight', pad_inches=0.3)
```

### 3. Chart Placement & Section Separation Rule
- Place **Chart 1** (Laptop Vulnerability Distribution) directly inside **Section 2.1**.
- Place **Chart 2** (Web Server Vulnerability Distribution) directly inside **Section 2.2**.
- Place the Delta Comparison Table & Risk Narrative inside **Section 2.3**.

### 4. Severity Localization & Filtering Rule
- Exclude all `INFORMATIONAL` / `INFO` level findings.
- Localize all severities to 100% Vietnamese:
  - `CRITICAL` $\rightarrow$ **NGHIÊM TRỌNG** (Bold Red `#FF0000`)
  - `HIGH` $\rightarrow$ **CAO** (Bold Dark Red `#C00000`)
  - `MEDIUM` $\rightarrow$ **TRUNG BÌNH** (Bold Orange `#ED7D31`)
  - `LOW` $\rightarrow$ **THẤP** (Bold Blue `#4472C4`)

### 5. Evidence & Callout Box Formatting
- Title evidence sections as **"Bằng chứng:"**.
- Wrap evidence content inside a single-cell 1x1 table (`Table Grid` style) with soft background shading (`#F9F9F9`).

### 6. Strict Table Pagination & Layout Controls
- Attach `<w:cantSplit/>` to `w:trPr` of ALL table rows to prevent rows from breaking mid-cell across page splits.
- Attach `<w:tblHeader/>` to `w:trPr` of row 0 on all data tables so headers repeat automatically on subsequent pages.
- Set `paragraph_format.keep_with_next = True` on all Headings (Heading 1, 2, 3).

### 7. Dual Table of Contents (TOC) Rule
- Include both a structured 2-column visual table (`NỘI DUNG CẤU TRÚC BÁO CÁO` | `TRANG`) and a native Word field (`TOC \o "1-3" \h \z \u`).

--------------------------------------------------------------------------------

## Automated Standard Execution Workflow

1. **Phase 1: Template Analysis (Optional for New Templates)**
   `python3 docx_analysis_tools/analyze_docx_template.py <template.docx>`

2. **Phase 2: Data Extraction & Persistence**
   `python3 docx_analysis_tools/persist_knowledge_base.py`

3. **Phase 3: Master Report Generation**
   `python3 docx_analysis_tools/build_perfection_report.py`

4. **Phase 4: 16-Assertion Automated Quality Audit**
   `python3 docx_analysis_tools/validate_report_perfection.py Bao_Cao_An_Toan_Thong_Tin_2026.docx`
