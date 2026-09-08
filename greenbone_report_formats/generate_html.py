#!/usr/bin/env python3
"""
DVAS HTML Report Generator for Greenbone Vulnerability Management (GVM/OpenVAS)
Brand: DVAS Security Intelligence Platform
Output: Standalone, offline-capable, interactive HTML report with zero external dependencies.
"""

import os
import sys
import re
import html
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# Severity color definitions matching enterprise vulnerability reporting standards
SEV_COLORS = {
    'Critical': '#91243E',
    'High': '#DD4B50',
    'Medium': '#F18C43',
    'Low': '#F8C851',
    'Info': '#67ACE1',
    'Log': '#67ACE1'
}

SEV_ORDER = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Info': 0,
    'Log': 0
}


def is_safe_url(url):
    """
    Validate that a URL string is safe to render in an <a href> tag.
    Strictly permits only http and https schemes with a valid network location.
    Rejects javascript:, data:, vbscript:, file:, about:, and control characters.
    """
    if not url or not isinstance(url, str):
        return False
    url_clean = url.strip()
    if not url_clean:
        return False
    # Immediately reject known dangerous protocol prefixes (case-insensitive)
    lower = url_clean.lower()
    if lower.startswith(('javascript:', 'data:', 'vbscript:', 'file:', 'about:')):
        return False
    try:
        parts = urllib.parse.urlsplit(url_clean)
        return parts.scheme in ('http', 'https') and bool(parts.netloc)
    except Exception:
        return False


def parse_openvas_tags(tags_str):
    """
    Robustly parse OpenVAS key=value|key=value tags.
    Handles pipes or equals inside tag descriptions without truncating content.
    """
    if not tags_str:
        return {}
    pattern = r'([a-zA-Z_]+)='
    matches = list(re.finditer(pattern, tags_str))
    res = {}
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(tags_str)
        val = tags_str[start:end].rstrip('|').strip()
        res[key] = val
    return res


def map_severity(score_str, threat_str):
    """
    Normalize severity to Critical, High, Medium, Low, or Info.
    """
    try:
        score = float(score_str)
    except (ValueError, TypeError):
        score = 0.0

    threat = (threat_str or '').strip().capitalize()

    if score >= 9.0 or threat == 'Critical':
        return 'Critical', max(score, 9.0)
    elif score >= 7.0 or threat == 'High':
        return 'High', max(score, 7.0)
    elif score >= 4.0 or threat == 'Medium':
        return 'Medium', max(score, 4.0)
    elif score > 0.0 or threat == 'Low':
        return 'Low', max(score, 0.1)
    else:
        return 'Info', 0.0


def extract_report_data(xml_source):
    """
    Extracts scan metadata and findings from OpenVAS raw XML.
    Guarantees 100% capture of valid scanner results (excluding sub-detection blocks).
    """
    if isinstance(xml_source, str) and os.path.isfile(xml_source):
        tree = ET.parse(xml_source)
        root = tree.getroot()
    elif isinstance(xml_source, str):
        root = ET.fromstring(xml_source)
    else:
        root = xml_source

    report_elem = root.find('.//report')
    if report_elem is None:
        report_elem = root

    # Metadata
    scan_name = "Vulnerability Assessment Scan"
    task_name_elem = report_elem.find('./task/name')
    if task_name_elem is not None and task_name_elem.text:
        scan_name = task_name_elem.text.strip()
    elif report_elem.get('id'):
        scan_name = f"Scan Report - {report_elem.get('id')[:8]}"

    scan_time = ""
    timestamp_elem = report_elem.find('./scan_start')
    if timestamp_elem is None:
        timestamp_elem = report_elem.find('./timestamp')
    if timestamp_elem is not None and timestamp_elem.text:
        scan_time = timestamp_elem.text.strip()
    else:
        scan_time = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")

    # Direct results selection (filters out internal sub-detection tags)
    raw_results = root.findall('.//results/result')
    valid_results = [
        r for r in raw_results
        if r.find('host') is not None and r.find('nvt') is not None
    ]

    findings = []
    hosts_set = set()
    cves_set = set()

    for idx, r in enumerate(valid_results):
        host_ip = (r.findtext('host') or 'Unknown Host').strip()
        hosts_set.add(host_ip)

        port = (r.findtext('port') or 'general/tcp').strip()
        raw_threat = (r.findtext('threat') or '').strip()
        raw_sev = (r.findtext('severity') or '0.0').strip()
        sev_label, sev_score = map_severity(raw_sev, raw_threat)

        nvt = r.find('nvt')
        name = (nvt.findtext('name') or r.findtext('name') or 'Vulnerability Finding').strip()
        oid = nvt.get('oid') or 'unknown-oid'
        family = (nvt.findtext('family') or 'General').strip()

        # Tags extraction
        tags_raw = nvt.findtext('tags') or ''
        tags = parse_openvas_tags(tags_raw)

        synopsis = tags.get('summary') or tags.get('insight') or name
        description = tags.get('insight') or tags.get('summary') or name
        solution = tags.get('solution') or 'No remediation information provided.'
        solution_type = tags.get('solution_type') or 'Mitigation'
        impact = tags.get('impact') or 'Information not available.'
        affected = tags.get('affected') or 'Information not available.'
        vuldetect = tags.get('vuldetect') or ''

        # Scanner raw output / evidence
        scanner_output = (r.findtext('description') or '').strip()

        # References
        cve_list = []
        cwe_list = []
        url_list = []
        for ref in nvt.findall('./refs/ref'):
            ref_type = (ref.get('type') or '').lower()
            ref_id = (ref.get('id') or ref.text or '').strip()
            if not ref_id:
                continue
            if ref_type == 'cve':
                cve_list.append(ref_id)
                cves_set.add(ref_id)
            elif ref_type == 'cwe':
                cwe_list.append(ref_id)
            elif ref_type == 'url':
                url_list.append(ref_id)

        # CVSS base vector & QoD
        cvss_vector = tags.get('cvss_base_vector') or ''
        if not cvss_vector:
            for s in nvt.findall('./severities/severity'):
                val = s.findtext('value')
                if val and 'CVSS' in val:
                    cvss_vector = val.strip()
                    break

        qod_val = (r.findtext('./qod/value') or '70').strip()
        qod_type = (r.findtext('./qod/type') or 'remote_probe').strip()

        finding_dict = {
            'index': idx + 1,
            'host': host_ip,
            'port': port,
            'name': name,
            'oid': oid,
            'family': family,
            'severity_label': sev_label,
            'severity_score': sev_score,
            'raw_severity': raw_sev,
            'raw_threat': raw_threat,
            'synopsis': synopsis,
            'description': description,
            'solution': solution,
            'solution_type': solution_type,
            'impact': impact,
            'affected': affected,
            'vuldetect': vuldetect,
            'scanner_output': scanner_output,
            'cve_list': sorted(list(set(cve_list))),
            'cwe_list': sorted(list(set(cwe_list))),
            'url_list': url_list,
            'cvss_vector': cvss_vector,
            'qod': f"{qod_val}% ({qod_type})"
        }
        findings.append(finding_dict)

    # Sort findings by severity score descending, then host, then port
    findings.sort(key=lambda x: (SEV_ORDER.get(x['severity_label'], 0), x['severity_score']), reverse=True)

    # Calculate severity counts
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for f in findings:
        lbl = f['severity_label']
        if lbl in counts:
            counts[lbl] += 1
        else:
            counts['Info'] += 1

    return {
        'scan_name': scan_name,
        'scan_time': scan_time,
        'hosts': sorted(list(hosts_set)),
        'findings': findings,
        'counts': counts,
        'unique_cves_count': len(cves_set),
        'unique_hosts_count': len(hosts_set),
        'total_findings_count': len(findings)
    }


def generate_html_report(data):
    """
    Generates a high-fidelity, interactive DVAS Security HTML Report.
    """
    scan_name = html.escape(data['scan_name'], quote=True)
    scan_time = html.escape(data['scan_time'], quote=True)
    hosts = data['hosts']
    findings = data['findings']
    counts = data['counts']
    total_vulns = data['total_findings_count']

    # Group findings by host
    hosts_findings = {}
    for h in hosts:
        hosts_findings[h] = [f for f in findings if f['host'] == h]

    # Generate Top Remediations summary table (group by solution / affected)
    remediation_items = []
    seen_remeds = set()
    for f in findings:
        if f['severity_label'] in ('Critical', 'High') and f['solution'] and f['solution'] != 'No remediation information provided.':
            short_sol = f['solution'].split('\n')[0][:120]
            key = (f['name'], short_sol)
            if key not in seen_remeds:
                seen_remeds.add(key)
                remediation_items.append({
                    'name': f['name'],
                    'action': f['solution'],
                    'severity': f['severity_label'],
                    'host': f['host']
                })
        if len(remediation_items) >= 15:
            break

    # Build HTML string
    out = []
    out.append('<!DOCTYPE html>')
    out.append('<html lang="en">')
    out.append('<head>')
    out.append('  <meta charset="utf-8">')
    out.append('  <meta name="viewport" content="width=device-width, initial-scale=1.0">')
    out.append(f'  <title>DVAS Security Intelligence Report - {scan_name}</title>')
    out.append('  <style>')
    out.append('''
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #f1f5f9;
            color: #1e293b;
            line-height: 1.5;
            font-size: 13px;
        }
        a {
            color: #2563eb;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .report-container {
            width: 100%;
            max-width: 1060px;
            margin: 25px auto;
            background: #ffffff;
            border-radius: 6px;
            box-shadow: 0 4px 16px rgba(15, 23, 42, 0.08);
            border-top: 4px solid #1e3a8a;
            padding: 24px 30px 40px 30px;
        }
        /* DVAS Header Styling */
        header.dvas-header {
            width: 100%;
            border-bottom: 1px dotted #cbd5e1;
            padding-bottom: 18px;
            margin-bottom: 22px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .dvas-brand-badge {
            background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
            color: #ffffff;
            padding: 8px 18px;
            border-radius: 6px;
            font-weight: 900;
            font-size: 26px;
            letter-spacing: 2px;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.25);
            display: inline-block;
        }
        .dvas-brand-desc {
            margin-left: 16px;
            border-left: 2px solid #cbd5e1;
            padding-left: 16px;
            display: inline-block;
            vertical-align: middle;
        }
        .dvas-title-main {
            font-size: 16px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: 0.5px;
        }
        .dvas-subtitle {
            font-size: 11px;
            color: #64748b;
            font-weight: 500;
        }
        .dvas-gen-tag {
            text-align: right;
        }
        .dvas-gen-tag h2 {
            font-size: 14px;
            font-weight: 700;
            color: #334155;
        }
        .dvas-gen-tag div {
            font-size: 11px;
            color: #64748b;
        }
        .scan-meta-box {
            margin-bottom: 25px;
        }
        .scan-meta-box h3 {
            font-size: 22px;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 4px;
        }
        .scan-meta-box h4 {
            color: #64748b;
            font-weight: 500;
            font-size: 12px;
            border-bottom: 1px dotted #cbd5e1;
            padding-bottom: 14px;
        }
        /* Severity 5-Box Grid */
        .sev-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin: 20px 0 30px 0;
        }
        .sev-card {
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 6px rgba(0,0,0,0.06);
            border: 1px solid #e2e8f0;
            background: #ffffff;
            text-align: center;
        }
        .sev-card-count {
            color: #ffffff;
            font-size: 38px;
            font-weight: 300;
            line-height: 70px;
        }
        .sev-card-label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 6px 0;
            background: #ffffff;
            color: #334155;
            border-top: 1px solid rgba(0,0,0,0.05);
        }
        /* Table of Contents */
        .toc-section {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 16px 20px;
            margin-bottom: 28px;
        }
        .toc-title {
            font-size: 13px;
            font-weight: 800;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            color: #1e3a8a;
            margin-bottom: 10px;
        }
        .toc-list {
            list-style: none;
        }
        .toc-list li {
            margin-bottom: 6px;
            font-size: 13px;
        }
        .toc-list li strong {
            color: #0f172a;
        }
        .toc-sublist {
            list-style: disc;
            margin-left: 24px;
            margin-top: 4px;
        }
        /* Section Header & Expand/Collapse */
        .section-bar {
            padding: 14px 0;
            border-top: 1px dotted #cbd5e1;
            border-bottom: 1px dotted #cbd5e1;
            margin: 28px 0 16px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-bar h4 {
            font-size: 18px;
            font-weight: 600;
            color: #0f172a;
        }
        .expand-controls {
            font-size: 12px;
        }
        .expand-btn {
            color: #2563eb;
            cursor: pointer;
            font-weight: 600;
        }
        .expand-btn:hover {
            text-decoration: underline;
        }
        .host-header {
            font-size: 18px;
            font-weight: 700;
            color: #0f172a;
            padding: 12px 0 10px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .host-badge {
            background: #e2e8f0;
            color: #334155;
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        /* Vulnerability Accordion Card */
        .vuln-item {
            margin-bottom: 14px;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            overflow: hidden;
            background: #ffffff;
            break-inside: avoid;
            page-break-inside: avoid;
        }
        .vuln-header-row {
            display: flex;
            align-items: center;
            cursor: pointer;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
            padding: 10px 14px;
            user-select: none;
            transition: background 0.15s ease;
        }
        .vuln-header-row:hover {
            background: #f1f5f9;
        }
        .vuln-sev-badge {
            color: #ffffff;
            font-size: 11px;
            font-weight: 800;
            padding: 4px 10px;
            border-radius: 3px;
            text-transform: uppercase;
            min-width: 65px;
            text-align: center;
            margin-right: 12px;
            letter-spacing: 0.5px;
        }
        .vuln-port-badge {
            background: #e2e8f0;
            color: #475569;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 8px;
            border-radius: 3px;
            margin-right: 12px;
            white-space: nowrap;
        }
        .vuln-title-text {
            font-size: 14px;
            font-weight: 700;
            color: #0f172a;
            flex-grow: 1;
        }
        .vuln-toggle-icon {
            font-size: 16px;
            font-weight: 700;
            color: #64748b;
            padding-left: 10px;
            min-width: 20px;
            text-align: center;
        }
        .vuln-body {
            padding: 16px 20px 20px 20px;
            display: block;
            line-height: 1.6;
        }
        .detail-block-title {
            font-size: 13px;
            font-weight: 700;
            color: #1e3a8a;
            border-bottom: 1px dotted #cbd5e1;
            padding-bottom: 4px;
            margin-top: 16px;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .detail-block-title:first-child {
            margin-top: 0;
        }
        .detail-content {
            font-size: 13px;
            color: #334155;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
        }
        /* Metadata table inside card */
        .meta-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 6px;
            font-size: 12px;
        }
        .meta-table td {
            padding: 6px 8px;
            border-bottom: 1px solid #f1f5f9;
        }
        .meta-table td.meta-label {
            font-weight: 700;
            color: #475569;
            width: 160px;
            background: #f8fafc;
        }
        .meta-table td.meta-val {
            color: #0f172a;
        }
        /* Evidence & Scanner Output */
        .evidence-box {
            background: #0f172a;
            color: #e2e8f0;
            padding: 12px 16px;
            border-radius: 5px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 6px;
            border: 1px solid #1e293b;
        }
        /* Tag Badges */
        .badge-tag {
            display: inline-block;
            background: #eff6ff;
            color: #1d4ed8;
            border: 1px solid #bfdbfe;
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 11px;
            margin-right: 6px;
            margin-bottom: 4px;
            font-weight: 600;
        }
        /* Remediations Table */
        .remed-table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0 24px 0;
            font-size: 12px;
        }
        .remed-table th {
            background: #f1f5f9;
            color: #334155;
            font-weight: 700;
            text-align: left;
            padding: 8px 12px;
            border: 1px solid #e2e8f0;
        }
        .remed-table td {
            padding: 8px 12px;
            border: 1px solid #e2e8f0;
            vertical-align: top;
        }
        footer.dvas-footer {
            text-align: center;
            font-size: 11px;
            color: #94a3b8;
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px dotted #cbd5e1;
        }
        @media print {
            body {
                background: #ffffff;
                color: #000000;
            }
            .report-container {
                box-shadow: none;
                border: none;
                padding: 0;
                max-width: 100%;
            }
            .expand-controls {
                display: none;
            }
            .vuln-body {
                display: block !important;
            }
            .vuln-toggle-icon {
                display: none;
            }
        }
    ''')
    out.append('  </style>')
    out.append('</head>')
    out.append('<body>')

    out.append('<div class="report-container">')

    # DVAS Brand Header
    out.append('  <header class="dvas-header">')
    out.append('    <div style="display: flex; align-items: center;">')
    out.append('      <div class="dvas-brand-badge">DVAS</div>')
    out.append('      <div class="dvas-brand-desc">')
    out.append('        <div class="dvas-title-main">SECURITY INTELLIGENCE PLATFORM</div>')
    out.append('        <div class="dvas-subtitle">Vulnerability Assessment &amp; Threat Prioritization</div>')
    out.append('      </div>')
    out.append('    </div>')
    out.append('    <div class="dvas-gen-tag">')
    out.append('      <h2>Report generated by DVAS™</h2>')
    out.append('      <div>Automated Security Pipeline</div>')
    out.append('    </div>')
    out.append('  </header>')

    # Scan Title & Time
    out.append('  <div class="scan-meta-box">')
    out.append(f'    <h3>{scan_name}</h3>')
    out.append(f'    <h4>{scan_time}</h4>')
    out.append('  </div>')

    # 5-Severity Summary Blocks
    out.append('  <div class="sev-grid">')
    for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        c = counts.get(sev, 0)
        color = SEV_COLORS[sev]
        out.append('    <div class="sev-card">')
        out.append(f'      <div class="sev-card-count" style="background-color: {color};">{c}</div>')
        out.append(f'      <div class="sev-card-label">{sev}</div>')
        out.append('    </div>')
    out.append('  </div>')

    # Table of Contents
    out.append('  <div class="toc-section">')
    out.append('    <div class="toc-title">TABLE OF CONTENTS</div>')
    out.append('    <ul class="toc-list">')
    out.append('      <li>')
    out.append('        <a href="#vulnerabilities-by-host"><strong>Vulnerabilities by Host</strong></a>')
    out.append('        <ul class="toc-sublist">')
    for h in hosts:
        h_esc = html.escape(h, quote=True)
        h_count = len(hosts_findings.get(h, []))
        out.append(f'          <li><a href="#host_{h_esc}">{h_esc}</a> ({h_count} findings)</li>')
    out.append('        </ul>')
    out.append('      </li>')
    if remediation_items:
        out.append('      <li style="margin-top: 8px;">')
        out.append('        <a href="#remediations"><strong>Remediations &amp; Recommended Actions</strong></a>')
        out.append('      </li>')
    out.append('    </ul>')
    out.append('  </div>')

    # Remediations Section
    if remediation_items:
        out.append('  <div class="section-bar" id="remediations">')
        out.append('    <h4>Top Suggested Remediations</h4>')
        out.append('  </div>')
        out.append('  <table class="remed-table">')
        out.append('    <thead>')
        out.append('      <tr>')
        out.append('        <th style="width: 100px;">Severity</th>')
        out.append('        <th>Vulnerability &amp; Action Required</th>')
        out.append('        <th style="width: 140px;">Target Host</th>')
        out.append('      </tr>')
        out.append('    </thead>')
        out.append('    <tbody>')
        for item in remediation_items:
            sev = item['severity']
            color = SEV_COLORS.get(sev, '#64748b')
            vuln_n = html.escape(item['name'], quote=True)
            act_n = html.escape(item['action'], quote=True)
            host_n = html.escape(item['host'], quote=True)
            out.append('      <tr>')
            out.append(f'        <td><span class="vuln-sev-badge" style="background-color: {color}; display: inline-block;">{sev}</span></td>')
            out.append(f'        <td><strong>{vuln_n}</strong><br><span style="color: #475569;">{act_n}</span></td>')
            out.append(f'        <td><code>{host_n}</code></td>')
            out.append('      </tr>')
        out.append('    </tbody>')
        out.append('  </table>')

    # Vulnerabilities By Host Section
    out.append('  <div class="section-bar" id="vulnerabilities-by-host">')
    out.append(f'    <h4>Vulnerabilities by Host ({total_vulns} total)</h4>')
    out.append('    <div class="expand-controls">')
    out.append('      <span class="expand-btn" onclick="toggleAll(false);">Expand All</span> | ')
    out.append('      <span class="expand-btn" onclick="toggleAll(true);">Collapse All</span>')
    out.append('    </div>')
    out.append('  </div>')

    # Render Host Findings
    card_counter = 0
    for h in hosts:
        h_esc = html.escape(h, quote=True)
        h_vulns = hosts_findings.get(h, [])
        out.append(f'  <div class="host-header" id="host_{h_esc}">')
        out.append(f'    <span>Host: <code>{h_esc}</code></span>')
        out.append(f'    <span class="host-badge">{len(h_vulns)} findings</span>')
        out.append('  </div>')

        for f in h_vulns:
            card_counter += 1
            idx = card_counter
            sev_label = f['severity_label']
            color = SEV_COLORS.get(sev_label, '#64748b')
            name_esc = html.escape(f['name'], quote=True)
            port_esc = html.escape(f['port'], quote=True)
            score_esc = html.escape(str(f['severity_score']), quote=True)

            out.append(f'  <div class="vuln-item" id="vuln_item_{idx}">')
            out.append(f'    <div class="vuln-header-row" onclick="toggleVuln({idx});">')
            out.append(f'      <div class="vuln-sev-badge" style="background-color: {color};">{sev_label} {score_esc}</div>')
            out.append(f'      <div class="vuln-port-badge">{port_esc}</div>')
            out.append(f'      <div class="vuln-title-text">{name_esc}</div>')
            out.append(f'      <div class="vuln-toggle-icon" id="toggle_icon_{idx}">-</div>')
            out.append('    </div>')

            # Expandable Card Body
            out.append(f'    <div class="vuln-body" id="vuln_body_{idx}">')

            # Synopsis
            if f['synopsis']:
                syn_esc = html.escape(f['synopsis'], quote=True)
                out.append('      <div class="detail-block-title">Synopsis</div>')
                out.append(f'      <div class="detail-content">{syn_esc}</div>')

            # Description
            if f['description']:
                desc_esc = html.escape(f['description'], quote=True)
                out.append('      <div class="detail-block-title">Description</div>')
                out.append(f'      <div class="detail-content">{desc_esc}</div>')

            # Solution
            if f['solution']:
                sol_esc = html.escape(f['solution'], quote=True)
                out.append('      <div class="detail-block-title">Solution</div>')
                out.append(f'      <div class="detail-content">{sol_esc}</div>')

            # See Also / URLs
            if f['url_list']:
                out.append('      <div class="detail-block-title">See Also</div>')
                out.append('      <ul style="margin-left: 20px; font-size: 12px;">')
                for u in f['url_list']:
                    u_clean = (u or '').strip()
                    u_esc = html.escape(u_clean, quote=True)
                    if is_safe_url(u_clean):
                        out.append(f'        <li><a href="{u_esc}" target="_blank" rel="noopener noreferrer">{u_esc}</a></li>')
                    else:
                        out.append(f'        <li><span class="unsafe-url">{u_esc}</span></li>')
                out.append('      </ul>')

            # Risk Information Table
            out.append('      <div class="detail-block-title">Risk Information</div>')
            out.append('      <table class="meta-table">')
            out.append(f'        <tr><td class="meta-label">Risk Factor</td><td class="meta-val"><strong style="color: {color};">{sev_label}</strong> (Score: {score_esc})</td></tr>')
            if f['cvss_vector']:
                vec_esc = html.escape(f['cvss_vector'], quote=True)
                out.append(f'        <tr><td class="meta-label">CVSS Base Vector</td><td class="meta-val"><code>{vec_esc}</code></td></tr>')
            if f['qod']:
                qod_esc = html.escape(f['qod'], quote=True)
                out.append(f'        <tr><td class="meta-label">Quality of Detection (QoD)</td><td class="meta-val">{qod_esc}</td></tr>')
            if f['solution_type']:
                st_esc = html.escape(f['solution_type'], quote=True)
                out.append(f'        <tr><td class="meta-label">Solution Type</td><td class="meta-val">{st_esc}</td></tr>')
            out.append('      </table>')

            # Vulnerability Information (CVE / CWE)
            if f['cve_list'] or f['cwe_list']:
                out.append('      <div class="detail-block-title">Vulnerability Information</div>')
                out.append('      <div style="margin-top: 6px;">')
                if f['cve_list']:
                    out.append('        <div style="margin-bottom: 6px;"><strong>CVEs:</strong> ')
                    for cve in f['cve_list']:
                        cve_clean = (cve or '').strip()
                        cve_esc = html.escape(cve_clean, quote=True)
                        cve_encoded = urllib.parse.quote(cve_clean)
                        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_encoded}"
                        out.append(f'<a href="{nvd_url}" target="_blank" rel="noopener noreferrer" class="badge-tag">{cve_esc}</a>')
                    out.append('        </div>')
                if f['cwe_list']:
                    out.append('        <div><strong>CWEs:</strong> ')
                    for cwe in f['cwe_list']:
                        cwe_clean = (cwe or '').strip()
                        cwe_esc = html.escape(cwe_clean, quote=True)
                        cwe_id = re.sub(r'[^0-9]', '', cwe_clean)
                        if cwe_id:
                            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                            out.append(f'<a href="{cwe_url}" target="_blank" rel="noopener noreferrer" class="badge-tag" style="background:#f0fdf4; color:#15803d; border-color:#bbf7d0;">{cwe_esc}</a>')
                        else:
                            out.append(f'<span class="badge-tag" style="background:#f0fdf4; color:#15803d; border-color:#bbf7d0;">{cwe_esc}</span>')
                    out.append('        </div>')
                out.append('      </div>')

            # Plugin Details Table
            out.append('      <div class="detail-block-title">Plugin Details</div>')
            out.append('      <table class="meta-table">')
            out.append(f'        <tr><td class="meta-label">Plugin ID (OID)</td><td class="meta-val"><code>{html.escape(f["oid"], quote=True)}</code></td></tr>')
            out.append(f'        <tr><td class="meta-label">Plugin Family</td><td class="meta-val">{html.escape(f["family"], quote=True)}</td></tr>')
            if f['affected'] and f['affected'] != 'Information not available.':
                out.append(f'        <tr><td class="meta-label">Affected Software</td><td class="meta-val">{html.escape(f["affected"], quote=True)}</td></tr>')
            out.append('      </table>')

            # Scanner Output / Evidence
            if f['scanner_output']:
                so_esc = html.escape(f['scanner_output'], quote=True)
                out.append('      <div class="detail-block-title">Scanner Output / Evidence</div>')
                out.append(f'      <div class="evidence-box">{so_esc}</div>')

            out.append('    </div>')  # vuln-body
            out.append('  </div>')  # vuln-item

    # DVAS Brand Footer
    out.append('  <footer class="dvas-footer">')
    out.append('    <div>© 2026 DVAS Security Intelligence Platform. All rights reserved. | Powered by Greenbone Vulnerability Management</div>')
    out.append('  </footer>')

    out.append('</div>')  # report-container

    # Interactive JavaScript
    out.append('''
  <script>
    function toggleVuln(idx) {
      var body = document.getElementById('vuln_body_' + idx);
      var icon = document.getElementById('toggle_icon_' + idx);
      if (!body) return;
      if (body.style.display === 'none') {
        body.style.display = 'block';
        if (icon) icon.innerText = '-';
      } else {
        body.style.display = 'none';
        if (icon) icon.innerText = '+';
      }
    }

    function toggleAll(collapse) {
      var bodies = document.querySelectorAll('.vuln-body');
      var icons = document.querySelectorAll('.vuln-toggle-icon');
      bodies.forEach(function(b) {
        b.style.display = collapse ? 'none' : 'block';
      });
      icons.forEach(function(ic) {
        ic.innerText = collapse ? '+' : '-';
      });
    }
  </script>
    ''')

    out.append('</body>')
    out.append('</html>')

    return '\n'.join(out)


def main():
    if len(sys.argv) < 2:
        print("Usage: generate_html.py <report_xml_file> [output_html_file]", file=sys.stderr)
        sys.exit(1)

    xml_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(xml_path):
        print(f"Error: XML file not found: {xml_path}", file=sys.stderr)
        sys.exit(2)

    try:
        report_data = extract_report_data(xml_path)
        html_content = generate_html_report(report_data)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        else:
            # Write bytes to stdout buffer to prevent UTF-8 encoding errors
            sys.stdout.buffer.write(html_content.encode('utf-8'))
        sys.exit(0)
    except Exception as e:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(3)


if __name__ == '__main__':
    main()
