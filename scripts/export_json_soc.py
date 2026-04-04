import pandas as pd
import json
import os
import sys
from datetime import datetime

# ============== CẤU HÌNH ĐƯỜNG DẪN ĐỘNG ==============
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_EXCEL = os.path.join(PROJECT_ROOT, 'vuln_attack_report.xlsx')
OUTPUT_JSON = os.path.join(PROJECT_ROOT, 'vuln_report_soc.json')

def clean_text(text):
    """Làm sạch dữ liệu text, xử lý NaN"""
    if pd.isna(text) or text == "":
        return None
    return str(text).strip()

# === AUTO-REMEDIATION ENRICHMENT ===
REMEDIATION_DB = {
    # Apache HTTP Server
    'apache': 'Update Apache HTTP Server to the latest stable version. Apply official security patches from https://httpd.apache.org/security/',
    'httpd': 'Update Apache HTTP Server to the latest stable version. Apply official security patches from https://httpd.apache.org/security/',
    # OpenSSH
    'openssh': 'Update OpenSSH to the latest version (>=9.6). Disable weak KEX/cipher/MAC algorithms in sshd_config.',
    'ssh': 'Update OpenSSH to the latest version. Review and harden sshd_config (disable password auth, use key-only, disable root login).',
    # SSL/TLS
    'ssl': 'Update SSL/TLS configuration: disable SSLv3, TLSv1.0, TLSv1.1. Use TLSv1.2+ with strong cipher suites.',
    'tls': 'Update SSL/TLS configuration: disable SSLv3, TLSv1.0, TLSv1.1. Use TLSv1.2+ with strong cipher suites.',
    'cipher': 'Disable weak cipher suites. Configure server to use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).',
    'kex': 'Disable weak Key Exchange algorithms (diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha1). Use curve25519-sha256.',
    'mac': 'Disable weak MAC algorithms (hmac-md5, hmac-sha1-96). Use hmac-sha2-256, hmac-sha2-512.',
    # Web vulnerabilities
    'sql injection': 'Use parameterized queries/prepared statements. Implement input validation and WAF rules.',
    'xss': 'Implement Content Security Policy headers. Sanitize user input. Use output encoding.',
    'csrf': 'Implement CSRF tokens on all forms. Use SameSite cookie attribute.',
    'path traversal': 'Validate and sanitize file paths. Use a whitelist of allowed directories. Disable directory listing.',
    '403': 'Review and fix access control configurations. Do not rely on client-side headers for authorization.',
    'terrapin': 'Update OpenSSH to >=9.6. Disable chacha20-poly1305@openssh.com and -etm@openssh.com MAC algorithms.',
    'crlf': 'Sanitize user input in HTTP headers. Use framework-provided header setting functions.',
    'denial of service': 'Apply vendor patches. Implement rate limiting and request size limits.',
    'buffer overflow': 'Update to patched version immediately. Enable ASLR and stack protections.',
    'privilege escalation': 'Apply vendor patches. Follow the principle of least privilege. Audit sudoers and SUID binaries.',
    'information disclosure': 'Remove version banners. Disable debug modes. Review server configuration for information leaks.',
    'user enumeration': 'Configure authentication to return generic error messages. Implement account lockout policies.',
}

def auto_remediation(finding_name, cve_str):
    """Generate remediation if none exists, based on finding name and CVE patterns."""
    if not finding_name:
        return None
    
    name_lower = str(finding_name).lower()
    
    # Check remediation DB by keyword match
    for keyword, fix in REMEDIATION_DB.items():
        if keyword in name_lower:
            return fix
    
    # Generic CVE-based remediation
    if cve_str and str(cve_str) != 'nan':
        cve_ids = str(cve_str).split(',')
        cve_urls = [f"https://nvd.nist.gov/vuln/detail/{c.strip()}" for c in cve_ids[:3] if c.strip()]
        return f"Apply vendor patch for {cve_ids[0].strip()}. See: {', '.join(cve_urls)}"
    
    return "Review finding details and apply vendor-recommended mitigation."

def detect_scan_mode(df):
    """Phát hiện chế độ dựa trên dữ liệu cột agent_status"""
    if 'agent_status' not in df.columns: return "UNKNOWN"
    
    statuses = set(df['agent_status'].dropna().astype(str).unique())
    
    # Từ khóa của chế độ Active Verify (Prompt V4.9)
    active_keys = {'REPRODUCED', 'CONFIRMED_PRESENT', 'CHECKED_NO_EXPLOIT', 'NOT_REPRODUCED'}
    # Từ khóa của chế độ Fast Scan
    fast_keys = {'WEAPONIZED', 'POTENTIAL', 'SKIPPED_NO_CVE'}
    
    # Kiểm tra giao thoa tập hợp
    if not statuses.isdisjoint(active_keys): return "ACTIVE_VERIFICATION"
    if not statuses.isdisjoint(fast_keys): return "FAST_SCAN"
    return "UNKNOWN"

def parse_to_soc_json():
    print(f"📊 [SOC] Đang tối ưu hóa dữ liệu và xuất JSON...")
    
    if not os.path.exists(INPUT_EXCEL):
        print(f"❌ Không tìm thấy file: {INPUT_EXCEL}")
        return

    try:
        df = pd.read_excel(INPUT_EXCEL)
    except Exception as e:
        print(f"❌ Lỗi đọc Excel: {e}")
        return

    scan_mode = detect_scan_mode(df)
    timestamp = datetime.now().isoformat()
    soc_logs = []

    print(f"   -> Chế độ phát hiện: {scan_mode}")

    for _, row in df.iterrows():
        # --- 1. LỌC VÀ ƯU TIÊN DỮ LIỆU ---
        
        # Priority: Ưu tiên P1, P2...
        prio = clean_text(row.get('priority', 'Info'))
        
        # Risk Score: Dùng điểm tổng hợp thay vì CVSS đơn lẻ
        score = row.get('risk_score', 0)
        
        # Target: Gộp Asset và URL/Port thành một định danh duy nhất
        asset = clean_text(row.get('asset', 'unknown'))
        location = clean_text(row.get('url_or_port', ''))
        target_str = f"{asset} ({location})" if location and location != asset else asset

        # Evidence: QUAN TRỌNG NHẤT - Lấy Active Evidence đè lên Evidence gốc
        # Nếu Active Verify có bằng chứng -> Dùng nó.
        # Nếu không, mới dùng evidence gốc của Scanner.
        agent_evidence = clean_text(row.get('agent_evidence'))
        raw_evidence = clean_text(row.get('evidence'))
        
        final_proof = agent_evidence if agent_evidence else raw_evidence
        
        # Status:
        status = clean_text(row.get('agent_status', 'Pending'))

        # --- 2. CẤU TRÚC JSON ---
        log_entry = {
            "timestamp": timestamp,
            "scan_mode": scan_mode,
            "alert": {
                "name": clean_text(row.get('finding_name')),
                "priority": prio,
                "score": score,
                "cve": clean_text(row.get('cve')),
                "mitre_technique": clean_text(row.get('attack_technique_id')), # Chỉ lấy ID (T1046) cho gọn
            },
            "target": {
                "host": asset,
                "location": location,
                "full": target_str
            },
            "analysis": {
                "status": status,
                "proof": final_proof, # Đây là trường SOC Analyst cần đọc nhất
                "epss_probability": row.get('epss_score', 0.0)
            },
            "remediation": {
                "fix": clean_text(row.get('solution')) or auto_remediation(
                    clean_text(row.get('finding_name')),
                    clean_text(row.get('cve'))
                )
            }
        }

        # --- 3. LOGIC GẮN NHÃN RIÊNG (CONTEXT) ---
        
        if scan_mode == "ACTIVE_VERIFICATION":
            # Chế độ Active: Quan tâm "Có hack được không?"
            if status in ['REPRODUCED', 'CONFIRMED_PRESENT']:
                log_entry["soc_context"] = "CRITICAL_ACTION_REQUIRED"
                log_entry["analysis"]["message"] = "Agent đã xác minh thành công lỗ hổng này."
            elif status == 'CHECKED_NO_EXPLOIT':
                log_entry["soc_context"] = "FALSE_POSITIVE_FILTERED"
                log_entry["analysis"]["message"] = "Agent đã kiểm tra nhưng không khai thác được."
            else:
                log_entry["soc_context"] = "INFO"

        elif scan_mode == "FAST_SCAN":
            # Chế độ Fast: Quan tâm "Có mã khai thác công khai không?"
            if status == 'WEAPONIZED':
                log_entry["soc_context"] = "THREAT_INTEL_MATCH"
                log_entry["analysis"]["message"] = "Phát hiện mã khai thác công khai (Exploit-DB/Nuclei)."
            else:
                log_entry["soc_context"] = "POTENTIAL_RISK"

        # Chỉ thêm log nếu có dữ liệu finding name (lọc dòng trống)
        if log_entry["alert"]["name"]:
            soc_logs.append(log_entry)

    # Xuất file
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(soc_logs, f, indent=4, ensure_ascii=False)

    print(f"✅ [SOC] Đã xuất {len(soc_logs)} logs tối ưu vào: {OUTPUT_JSON}")

if __name__ == "__main__":
    parse_to_soc_json()
