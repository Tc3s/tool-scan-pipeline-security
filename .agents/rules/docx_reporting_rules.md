# Comprehensive DOCX Reporting, Formatting & Debate Rules

## 0. MANDATORY CORE PRINCIPLE: SUBAGENT DEBATE & TRIPLE CROSS-CHECK
- **Always Debate & Critically Reflect**: NEVER accept initial assumptions, unverified subagent summaries, or partial script outputs at face value. Always challenge proposals, inspect failure states, and debate edge cases.
- **Mandatory Empirical Verification**: Every data point, finding count, CVE, CVSS score, and severe classification MUST be cross-checked 1:1 across 3 authoritative sources:
  1. Raw Scan Execution Outputs (`runs/run_.../output/*.csv`).
  2. Persistent JSON Knowledge Base (`docx_analysis_tools/full_vulnerability_knowledge_base.json`).
  3. Template Standards & Baseline Blueprint (`MAU REPORT.docx`).
- **No Declaration Without Verification**: An agent MUST NOT claim a DOCX report is complete until `docx_analysis_tools/validate_report_perfection.py` returns 100% PASS (16/16 assertions).

---

## 1. Overview & Purpose
This document governs all automated generation, formatting, and structural auditing of cybersecurity vulnerability assessment reports (`.docx`) within the pipeline. All generated reports MUST strictly adhere to these rules and pass 100% of the checks in `docx_analysis_tools/validate_report_perfection.py`.

---

## 2. Mandatory Structural & XML Rules

### Rule 1: Body XML Purging
- All template placeholder content in `w:body` MUST be removed directly at the XML level.
- `w:body` children MUST be purged EXCEPT for section properties (`sectPr`), which preserve margins, headers, and footers:
```python
for child in list(doc._element.body):
    if not child.tag.endswith('sectPr'):
        doc._element.body.remove(child)
```
- No orphan Structured Document Tag (`w:sdt`) elements may remain outside authorized field code blocks.

### Rule 2: 100% Vietnamese Severity Localization & Info Exclusion
- **Zero English Severity Strings**: The terms `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`, `INFO` are forbidden in any visual output.
- **Zero Informational Findings**: All `INFORMATIONAL` / `INFO` severity findings MUST be completely filtered out before report rendering.
- **Vietnamese Severity Color Scheme**:
  - `NGHIÊM TRỌNG` (Critical): Bold Red `#FF0000`
  - `CAO` (High): Bold Dark Red `#C00000`
  - `TRUNG BÌNH` (Medium): Bold Orange `#ED7D31`
  - `THẤP` (Low): Bold Blue `#4472C4`

### Rule 3: Zero HTML Tag Leakage
- Raw HTML tags (`<p>`, `</p>`, `<b>`, `<i>`, `<br>`, `<div>`, `<span>`, `<a>`, etc.) MUST be completely stripped using regex (`re.sub(r'<[^>]+>', '', text)`) and unescaped prior to document insertion.

### Rule 4: Zero Placeholder & Mock Text
- The text strings `(Mock)`, `Placeholder`, `TODO`, `FIXME`, `Lorem ipsum`, `Sample Text`, `[INSERT`, `TBD` are strictly forbidden.

### Rule 5: 100% Typography Uniformity (Times New Roman)
- Every paragraph, run, heading, and table cell MUST explicitly declare `Times New Roman` font.
- Both python-docx font properties (`run.font.name`) AND underlying OpenXML element properties (`w:rFonts` with `w:ascii`, `w:hAnsi`, and `w:cs`) MUST be configured to `Times New Roman`.

### Rule 6: Evidence & Callout Box Formatting
- Detailed vulnerability proof sections MUST be titled **"Bằng chứng:"**.
- Content MUST be encapsulated in a single-cell 1x1 table grid (`Table Grid` style) with soft grey background shading (`#F9F9F9`).
- The total count of evidence boxes MUST match the exact number of vulnerability findings in Section 3 and 4.

### Rule 7: Chart Generation & Section Alignment
- Exactly two matplotlib charts MUST be rendered and embedded as inline drawings (`w:drawing`):
  - **Chart 1** (Laptop Vulnerability Distribution) MUST be placed inside **Section 2.1**.
  - **Chart 2** (Web Server Vulnerability Distribution) MUST be placed inside **Section 2.2**.
- Charts MUST be exported with high DPI (300) and explicit padding (`bbox_inches='tight'`, `pad_inches=0.3`) to prevent clipping.

### Rule 8: Strict Pagination & Layout Controls
- **Table Row Splitting**: All table rows (`w:tr`) MUST contain `<w:cantSplit/>` in `w:trPr` to prevent rows from breaking across pages.
- **Orphan Prevention**: All heading paragraphs (Heading 1, 2, 3) MUST have `keep_with_next = True` (`<w:keepNext/>`).
- **Table Header Repeating**: Multi-row data tables MUST contain `<w:tblHeader/>` in the first row's `w:trPr`.

### Rule 9: Dual Table of Contents Requirement
- Generated reports MUST contain both:
  1. A structured 2-column visual table summary (`NỘI DUNG CẤU TRÚC BÁO CÁO` | `TRANG`).
  2. A native Word field code (`TOC \o "1-3" \h \z \u`).

---

## 3. Automated Validation Pipeline Integration
Every report build script MUST run `python3 docx_analysis_tools/validate_report_perfection.py <report_path.docx>` as a mandatory post-build verification step. An exit code of `0` denotes PASS; any non-zero exit code blocks delivery.
