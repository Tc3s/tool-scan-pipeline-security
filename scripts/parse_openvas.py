#!/usr/bin/env python3
try:
    import defusedxml.ElementTree as ET  # XXE protection
except ImportError:
    raise SystemExit("❌ defusedxml is required for parsing scanner XML safely. Install requirements.txt first.")
import csv
import os
from datetime import datetime

try:
    from scripts import runtime_context as rt
    from scripts.schema_utils import clean_text, extract_cves, extract_cwes, ids_to_csv, values_to_json
except ImportError:
    import runtime_context as rt
    from schema_utils import clean_text, extract_cves, extract_cwes, ids_to_csv, values_to_json


FIELDNAMES = [
    'scanner', 'scan_time', 'asset', 'asset_type', 'location', 'url_or_port',
    'finding_name', 'severity', 'cvss', 'cve', 'cve_list', 'cwe', 'cwe_list',
    'plugin_id', 'description', 'scanner_evidence', 'scanner_solution',
    'evidence', 'solution', 'evidence_solution', 'raw_reference',
    'instance_count', 'affected_urls_json'
]


def _text(elem, max_length=None):
    return clean_text(elem.text if elem is not None else "", max_length=max_length)


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def parse_openvas_xml(xml_path, output_csv):
    """Parse OpenVAS XML report to normalized CSV"""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise SystemExit(f"❌ Invalid OpenVAS XML: {exc}") from exc
    root = tree.getroot()
    
    findings = []
    
    # Get scan time
    report = root.find('.//report')
    scan_time = datetime.now().isoformat()
    if report is not None:
        st = report.find('.//scan_start')
        if st is not None:
            scan_time = st.text
    
    # Parse results
    for result in root.findall('.//result'):
        host = result.find('host')
        port = result.find('port')
        nvt = result.find('nvt')
        severity = result.find('severity')
        
        if host is None or nvt is None:
            continue
        
        severity_val = _safe_float(severity.text if severity is not None else None)
        
        # Map severity to category
        if severity_val >= 9.0:
            sev_cat = 'Critical'
        elif severity_val >= 7.0:
            sev_cat = 'High'
        elif severity_val >= 4.0:
            sev_cat = 'Medium'
        elif severity_val > 0.0:
            sev_cat = 'Low'
        else:
            sev_cat = 'Informational'
        
        # Extract CVEs
        cve_list = []
        for ref in nvt.findall('.//ref[@type="cve"]'):
            if ref.get('id'):
                cve_list.append(ref.get('id'))
        
        # Extract CWE (if exists)
        cwe_list = []
        for ref in nvt.findall('.//ref[@type="cwe"]'):
            if ref.get('id'):
                cwe_list.append(ref.get('id'))
        
        name_elem = nvt.find('name')
        desc_elem = result.find('description')
        solution_elem = result.find('.//solution')
        port_text = _text(port)
        description = _text(desc_elem, max_length=4000)
        solution = _text(solution_elem, max_length=4000)
        cves = extract_cves(cve_list)
        cwes = extract_cwes(cwe_list)
        plugin_id = nvt.get('oid', '') if nvt is not None else ''
        
        finding = {
            'scanner': 'OpenVAS',
            'scan_time': scan_time,
            'asset': _text(host),
            'asset_type': 'host',
            'location': port_text,
            'url_or_port': port_text,
            'finding_name': _text(name_elem) or 'Unknown',
            'severity': sev_cat,
            'cvss': f"{severity_val:.1f}",
            'cve': ids_to_csv(cves),
            'cve_list': values_to_json(cves),
            'cwe': ids_to_csv(cwes),
            'cwe_list': values_to_json(cwes),
            'plugin_id': plugin_id,
            'description': description,
            'scanner_evidence': description,
            'scanner_solution': solution,
            'evidence': description,
            'solution': solution,
            'evidence_solution': solution,
            'raw_reference': plugin_id,
            'instance_count': 1,
            'affected_urls_json': '[]',
        }
        findings.append(finding)
    
    # Write CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(findings)
    
    print(f"✅ Parsed {len(findings)} findings → {output_csv}")
    
    # Stats
    sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    cve_count = 0
    for f in findings:
        sev = f['severity']
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts[sev] = 1
        if f['cve']:
            cve_count += 1
    
    print(f"\nSeverity breakdown:")
    print(f"  Critical:      {sev_counts.get('Critical', 0)}")
    print(f"  High:          {sev_counts.get('High', 0)}")
    print(f"  Medium:        {sev_counts.get('Medium', 0)}")
    print(f"  Low:           {sev_counts.get('Low', 0)}")
    print(f"  Informational: {sev_counts.get('Informational', 0)}")
    print(f"\nFindings with CVE: {cve_count}")
    
    return len(findings)

if __name__ == '__main__':
    import sys
    import glob
    import os
    
    # Tìm thư mục gốc của project (script nằm trong scripts/)
    if len(sys.argv) > 1:
        xml_file = sys.argv[1]
    else:
        # Auto-detect: tìm file XML mới nhất trong data/raw/
        raw_dir = rt.raw_dir()
        xml_files = glob.glob(os.path.join(raw_dir, '*.xml'))
        if xml_files:
            xml_file = max(xml_files, key=os.path.getmtime)
            print(f"ℹ️  Auto-detected: {xml_file}")
        else:
            print(f"❌ Không tìm thấy file XML nào trong {raw_dir}")
            sys.exit(1)
    
    output_file = sys.argv[2] if len(sys.argv) > 2 else rt.normalized_dir() / 'openvas_findings.csv'
    parse_openvas_xml(xml_file, output_file)
