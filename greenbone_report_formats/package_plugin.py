#!/usr/bin/env python3
"""
Packager script for Greenbone DVAS HTML Report Format Plugin.
Encodes generator files into base64 and outputs a validated GMP XML import payload.
"""

import os
import sys
import base64
from pathlib import Path

FORMAT_UUID = "d7a1249b-8419-482a-9e7f-619da0e7b102"
FORMAT_NAME = "DVAS HTML Report"
EXTENSION = "html"
CONTENT_TYPE = "text/html"
REPORT_TYPE = "all"
SUMMARY = "Interactive DVAS Security Intelligence HTML Report."
DESCRIPTION = (
    "Generates a modern, interactive HTML vulnerability assessment report "
    "featuring DVAS branding, host-based table of contents, severity breakdown "
    "indicators, CVE/CWE cross-references, and expandable vulnerability detail cards."
)


def encode_file(filepath):
    with open(filepath, 'rb') as f:
        return base64.b64encode(f.read()).decode('ascii')


def build_package(src_dir, output_xml_path):
    src_dir = Path(src_dir)
    generate_path = src_dir / "generate"
    gen_py_path = src_dir / "generate_html.py"
    meta_path = src_dir / "report_format.xml"

    if not generate_path.exists():
        raise FileNotFoundError(f"Missing {generate_path}")
    if not gen_py_path.exists():
        raise FileNotFoundError(f"Missing {gen_py_path}")
    if not meta_path.exists():
        raise FileNotFoundError(f"Missing {meta_path}")

    b64_generate = encode_file(generate_path)
    b64_gen_py = encode_file(gen_py_path)
    b64_meta = encode_file(meta_path)

    xml_lines = [
        '<!-- Copyright (C) 2026 DVAS Security Intelligence Platform -->',
        '<get_report_formats_response status="200" status_text="OK">',
        f'  <report_format id="{FORMAT_UUID}">',
        f'    <name>{FORMAT_NAME}</name>',
        f'    <extension>{EXTENSION}</extension>',
        f'    <content_type>{CONTENT_TYPE}</content_type>',
        f'    <summary>{SUMMARY}</summary>',
        f'    <description>{DESCRIPTION}</description>',
        f'    <report_type>{REPORT_TYPE}</report_type>',
        f'    <file name="generate">{b64_generate}</file>',
        f'    <file name="generate_html.py">{b64_gen_py}</file>',
        f'    <file name="report_format.xml">{b64_meta}</file>',
        '  </report_format>',
        '</get_report_formats_response>'
    ]

    output_content = '\n'.join(xml_lines) + '\n'
    with open(output_xml_path, 'w', encoding='utf-8') as f:
        f.write(output_content)

    print(f"Successfully packaged DVAS Report Format to: {output_xml_path}")
    print(f"Total XML size: {len(output_content)} bytes")


if __name__ == '__main__':
    base_dir = Path(__file__).parent.resolve()
    target_output = base_dir / "greenbone_dvas_html_report_format.xml"
    build_package(base_dir, target_output)
