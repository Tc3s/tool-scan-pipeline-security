---
name: docx-template-analyzer
description: >-
  Standardized runbook and skill for performing deep, comprehensive structural, style, and XML analysis of DOCX template files.
  Use this skill whenever the user asks to analyze, deconstruct, audit, or extract formatting rules from any Word document (.docx).
---

# DOCX Template Analyzer Skill

This skill provides a systematic runbook and Python analysis scripts for performing deep inspection of Microsoft Word (`.docx`) template files, extracting typography, color palettes, heading hierarchies, table structures, callout boxes, and hidden XML elements (SDT blocks, field codes).

--------------------------------------------------------------------------------

## Analysis Procedure & Runbook

### Step 1: Deep Inspection Script Execution
Run the automated DOCX analyzer script to extract all structural parameters in JSON format:
```bash
python3 docx_analysis_tools/analyze_docx_template.py <path_to_docx>
```

### Step 2: Key Structural Aspects to Deconstruct

1. **Typography & Styling**:
   - Extract font families (`Times New Roman`, `Arial`, `Calibri`, etc.).
   - Extract Heading 1-3 sizes, font weights, colors, and line spacing.
   - Extract bullet point indents and paragraph spacing.

2. **Table Design & Cell Formatting**:
   - Count total tables, row/column dimensions.
   - Extract cell padding, border widths, header row background shading hex colors (e.g. `#D9D9D9`, `#F2F2F2`).
   - Identify single-cell callout boxes (1x1 tables used for Evidence, Notes, or Alerts) and their background shading (e.g. `#F9F9F9`).

3. **XML & Hidden Elements Inspection**:
   - Scan for `<w:sdt>` (Structured Document Tag) blocks in `w:body` that may cache old Table of Contents (TOC) entries or template placeholders.
   - Scan for native Word field codes (`TOC`, `PAGEREF`, `PAGE`, `NUMPAGES`).
   - Inspect section properties (`sectPr`), headers, and footers.

4. **Visual Assets & Drawings**:
   - Scan for inline drawings, shapes, logos, and embedded chart figures.
   - Record target dimensions and alignment.

5. **Document Outline & Tone Extraction**:
   - Extract the complete heading hierarchy to understand the expected document structure.
   - Analyze administrative tone, phrasing patterns, and technical terminology.

--------------------------------------------------------------------------------

## Output Artifacts

The analysis output should be summarized as a **Template Blueprint Artifact** covering:
- Document Hierarchy & TOC Outline
- Typography & Color System
- Table & Callout Grid Specs
- Hidden XML & Field Code Requirements
- Tone & Phrasing Guidelines
