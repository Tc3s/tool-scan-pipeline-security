#!/usr/bin/env python3
"""
CLI tool to generate a DVAS Interactive HTML Security Report from an OpenVAS raw XML file.
Can be used standalone or integrated into pipeline runs.
"""

import os
import sys
import argparse
from pathlib import Path

# Add project root to python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "greenbone_report_formats"))

from generate_html import extract_report_data, generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Generate interactive DVAS HTML vulnerability report from OpenVAS raw XML."
    )
    parser.add_argument(
        "xml_report",
        help="Path to the OpenVAS raw XML report file (e.g. runs/run_.../raw/report-*.xml)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output HTML file path (default: <xml_report_basename>.html in current directory)"
    )
    args = parser.parse_args()

    xml_path = Path(args.xml_report)
    if not xml_path.exists():
        print(f"Error: Input XML report not found: {xml_path}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(f"DVAS_Security_Report_{xml_path.stem}.html")

    print(f"[*] Parsing OpenVAS XML report: {xml_path}")
    data = extract_report_data(str(xml_path))
    print(f"[+] Successfully extracted {data['total_findings_count']} findings across {data['unique_hosts_count']} host(s)")
    print(f"[+] Extracted {data['unique_cves_count']} unique CVEs")
    print(f"[+] Severity breakdown: {data['counts']}")

    print(f"[*] Rendering interactive DVAS HTML report...")
    html_content = generate_html_report(data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[✔] DVAS HTML report saved to: {output_path.resolve()} ({len(html_content)} bytes)")


if __name__ == '__main__':
    main()
