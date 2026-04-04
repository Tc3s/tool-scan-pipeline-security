#!/usr/bin/env python3
try:
    import defusedxml.ElementTree as ET  # XXE protection
except ImportError:
    import xml.etree.ElementTree as ET
    print("⚠️  defusedxml not installed — using standard XML parser (XXE risk!)")
    print("   Install: pip install defusedxml")
import csv
from datetime import datetime

def parse_openvas_xml(xml_path, output_csv):
    """Parse OpenVAS XML report to normalized CSV"""
    tree = ET.parse(xml_path)
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
        
        severity_val = float(severity.text) if severity is not None else 0.0
        
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
            sev_cat = 'Log'
        
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
        
        finding = {
            'scanner': 'OpenVAS',
            'scan_time': scan_time,
            'asset': host.text,
            'asset_type': 'host',
            'url_or_port': port.text if port is not None else '',
            'finding_name': name_elem.text if name_elem is not None else 'Unknown',
            'severity': sev_cat,
            'cvss': f"{severity_val:.1f}",
            'cve': ','.join(cve_list),
            'cwe': ','.join(cwe_list),
            'description': (desc_elem.text or '')[:800] if desc_elem is not None else '',
            'evidence_solution': (solution_elem.text or '')[:500] if solution_elem is not None else ''
        }
        findings.append(finding)
    
    # Write CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['scanner', 'scan_time', 'asset', 'asset_type', 'url_or_port',
                      'finding_name', 'severity', 'cvss', 'cve', 'cwe', 
                      'description', 'evidence_solution']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
    
    print(f"✅ Parsed {len(findings)} findings → {output_csv}")
    
    # Stats
    sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Log': 0}
    cve_count = 0
    for f in findings:
        sev_counts[f['severity']] += 1
        if f['cve']:
            cve_count += 1
    
    print(f"\nSeverity breakdown:")
    print(f"  Critical: {sev_counts['Critical']}")
    print(f"  High:     {sev_counts['High']}")
    print(f"  Medium:   {sev_counts['Medium']}")
    print(f"  Low:      {sev_counts['Low']}")
    print(f"  Log:      {sev_counts['Log']}")
    print(f"\nFindings with CVE: {cve_count}")
    
    return len(findings)

if __name__ == '__main__':
    import sys
    import glob
    import os
    
    # Tìm thư mục gốc của project (script nằm trong scripts/)
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(PROJECT_ROOT, "data")
    
    if len(sys.argv) > 1:
        xml_file = sys.argv[1]
    else:
        # Auto-detect: tìm file XML mới nhất trong data/raw/
        raw_dir = os.path.join(DATA_DIR, 'raw')
        xml_files = glob.glob(os.path.join(raw_dir, '*.xml'))
        if xml_files:
            xml_file = max(xml_files, key=os.path.getmtime)
            print(f"ℹ️  Auto-detected: {xml_file}")
        else:
            print(f"❌ Không tìm thấy file XML nào trong {raw_dir}")
            sys.exit(1)
    
    output_file = sys.argv[2] if len(sys.argv) > 2 else os.path.join(DATA_DIR, 'normalized', 'openvas_findings.csv')
    parse_openvas_xml(xml_file, output_file)
