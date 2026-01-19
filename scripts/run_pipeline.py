#!/usr/bin/env python3

"""
🎯 MITRE ATT&CK + ZAP Vulnerability Scanner
(Features: ZAP Docker Only + Auto Venv + Tool Check + HEURISTIC AUDITOR PROMPT)
"""

import os
import sys
import subprocess
import time
import logging
import traceback
import shutil
from datetime import datetime

# ============== CẤU HÌNH HỆ THỐNG ==============
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
RAW_DIR = os.path.join("data", "raw")
JSON_REPORT = os.path.join(RAW_DIR, "zap_report.json")
HTML_REPORT = os.path.join(RAW_DIR, "zap_report.html")
LOG_FILE = "pipeline.log"

# ============== GIAO DIỆN ==============
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filemode='w')

class Debugger:
    @staticmethod
    def _timestamp(): return datetime.now().strftime("%H:%M:%S")
    @staticmethod
    def info(msg): ts = Debugger._timestamp(); print(f"{C.CYAN}[{ts}] ℹ️  {msg}{C.END}"); logging.info(msg)
    @staticmethod
    def success(msg): ts = Debugger._timestamp(); print(f"{C.GREEN}[{ts}] ✅ {msg}{C.END}"); logging.info(f"SUCCESS: {msg}")
    @staticmethod
    def warning(msg): ts = Debugger._timestamp(); print(f"{C.YELLOW}[{ts}] ⚠️  {msg}{C.END}"); logging.warning(msg)
    @staticmethod
    def error(msg): ts = Debugger._timestamp(); print(f"{C.RED}[{ts}] ❌ {msg}{C.END}"); logging.error(msg)
    @staticmethod
    def step(msg): print(f"\n{C.BOLD}{C.BLUE}▶️  STEP: {msg}{C.END}"); logging.info(f"--- STEP: {msg} ---")

# ============== HÀM HỖ TRỢ ==============

def get_python_exec():
    return sys.executable

def check_external_tools():
    """Kiểm tra xem các tool CLI quan trọng có tồn tại không"""
    Debugger.info("Checking external CLI tools...")
    tools = ["curl", "nmap", "sqlmap", "nikto", "wpscan", "nuclei"]
    missing = []
    found = []
    
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
        else:
            found.append(tool)
            
    if found:
        print(f"   ✅ Found: {', '.join(found)}")
        
    if missing:
        Debugger.warning(f"MISSING TOOLS: {', '.join(missing)}")
        print(f"   {C.YELLOW}👉 Recommendation: Install them OR the Agent will use Python fallbacks.{C.END}")
        return missing
    return []

def run_cmd(command, ignore_error=False):
    Debugger.info(f"Exec: {command}")
    start = time.time()
    try:
        subprocess.run(command, shell=True, check=True)
        duration = time.time() - start
        Debugger.success(f"Completed in {duration:.2f}s")
    except subprocess.CalledProcessError:
        duration = time.time() - start
        if not ignore_error:
            Debugger.error(f"Command failed after {duration:.2f}s")
            sys.exit(1)
        else:
            Debugger.warning(f"Command failed (Ignored)")

def check_directories():
    Debugger.info("Checking directory structure...")
    dirs = [
        os.path.join("data", "raw"),
        os.path.join("data", "normalized"),
        os.path.join("data", "output"),
        "scripts"
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def fix_permissions():
    if os.name != 'nt':
        try:
            uid = os.getuid(); gid = os.getgid()
            subprocess.run(f"sudo chown -R {uid}:{gid} data/", shell=True, stderr=subprocess.DEVNULL)
            Debugger.success("Permissions fixed.")
        except: pass

# ============== PHASE 1: SCANNING (ZAP ONLY) ==============
def run_scanning_phase():
    Debugger.step("PHASE 1: ACTIVE SCANNING (ZAP)")
    
    # Check Docker
    try: subprocess.run("docker --version", shell=True, check=True, stdout=subprocess.DEVNULL)
    except: Debugger.error("Docker missing! Cannot run ZAP."); sys.exit(1)

    print(f"\n{C.HEADER}--- TARGET CONFIG ---{C.END}")
    url = input(f"{C.BOLD}👉 Target URL (Default: http://scanme.nmap.org): {C.END}").strip() or "http://scanme.nmap.org"
    if not url.startswith("http"): url = "http://" + url
    
    print(f"\n{C.CYAN}[ ZAP SCAN MODES ]{C.END}")
    print("1. ⚡ Quick Baseline Scan")
    print("2. 🐢 Full Deep Scan (Recommended)")
    print("3. 🕷️ AJAX Spider Scan")
    
    choice = input(f"{C.BOLD}👉 Option (1-3): {C.END}").strip()
    script = "zap-baseline.py"; params = ""
    if choice == '2': script = "zap-full-scan.py"
    elif choice == '3': params = "-j"

    # Xóa report cũ
    if os.path.exists(JSON_REPORT):
        try: os.remove(JSON_REPORT); os.remove(HTML_REPORT)
        except: pass

    cwd = os.getcwd()
    cmd = (
        f"docker run --rm -u 0 -v \"{cwd}/data/raw\":/zap/wrk/:rw "
        f"-t {ZAP_IMAGE} {script} "
        f"-t {url} -J zap_report.json -r zap_report.html {params}"
    )
    run_cmd(cmd, ignore_error=True)
    fix_permissions()

    if not os.path.exists(JSON_REPORT): Debugger.error("No report generated!"); sys.exit(1)
    Debugger.success(f"Report saved: {JSON_REPORT}")

    # Nhắc nhở về OpenVAS (vì tool này chạy ngoài)
    print(f"\n{C.YELLOW}⚠️  IMPORTANT NOTE FOR OPENVAS:{C.END}")
    print("   Please run OpenVAS manually and save the XML report to:")
    print(f"   👉 {C.BOLD}data/raw/openvas_scanme_report.xml{C.END}")
    
    return url

# ============== PHASE 2: PROCESSING ==============
def run_processing_phase():
    Debugger.step("PHASE 2: DATA PROCESSING")
    if not os.path.exists(JSON_REPORT): Debugger.error("Missing Report"); return

    py = get_python_exec()
    s_parse_zap = os.path.join("scripts", "parse_zap.py")
    s_parse_openvas = os.path.join("scripts", "parse_openvas.py")
    s_merge = os.path.join("scripts", "merge_vulns.py")
    s_map = os.path.join("scripts", "apply_attack_mapping.py")
    s_risk = os.path.join("scripts", "calculate_risk_priority.py")

    run_cmd(f"\"{py}\" {s_parse_zap}")
    
    openvas_report = os.path.join(RAW_DIR, "openvas_scanme_report.xml")
    if os.path.exists(openvas_report):
        run_cmd(f"\"{py}\" {s_parse_openvas} \"{openvas_report}\" \"data/normalized/openvas_findings.csv\"")
    
    run_cmd(f"\"{py}\" {s_merge}")
    run_cmd(f"\"{py}\" {s_map}")
    run_cmd(f"\"{py}\" {s_risk}")
    
    Debugger.success("Processing Complete.")

# ============== PHASE 3: AGENT BRIDGE (HEURISTIC AUDITOR) ==============
def run_bridge_phase(target_url, missing_tools=[]):
    Debugger.step("PHASE 3: AGENT HANDOFF")
    
    # 1. Kiểm tra môi trường (Tool Check)
    tools_status = {
        "nuclei": shutil.which("nuclei") is not None,
        "sqlmap": shutil.which("sqlmap") is not None,
        "wpscan": shutil.which("wpscan") is not None,
        "nmap": shutil.which("nmap") is not None
    }
    
    # Chạy script bridge
    py = get_python_exec()
    s_bridge = os.path.join("scripts", "antigravity_agent_bridge.py")
    s_export = os.path.join("scripts", "export_excel.py")
    
    run_cmd(f"\"{py}\" {s_bridge}")
    
    try:
        rel_py = os.path.relpath(py, os.getcwd())
        agent_py_cmd = f"./{rel_py}" if not rel_py.startswith("..") and os.name != 'nt' else py
    except: agent_py_cmd = py

    # 2. IN PROMPT RA MÀN HÌNH
    print("\n" + "="*70)
    print(f"{C.HEADER}{C.BOLD}🚀  PIPELINE COMPLETED - HEURISTIC AUDITOR MODE READY  🚀{C.END}")
    print("="*70)
    print(f"✅ Data ready at: data/output/vuln_validation_queue.csv")
    print(f"✅ Context: Nuclei={tools_status['nuclei']}, SQLMap={tools_status['sqlmap']}, Nmap={tools_status['nmap']}")
    print(f"\n{C.YELLOW}👉 COPY THE PROMPT BELOW TO ANTIGRAVITY IDE:{C.END}")
    
    print(f"{C.CYAN}--------------------------------------------------{C.END}")
    
    # --- BẮT ĐẦU PROMPT ---
    print(f"You are an Elite Security Audit Engine.")
    print(f"TARGET INPUT: {target_url}")
    print(f"MISSION: Verify EVERY finding in 'data/output/vuln_validation_queue.csv' with 100% COMPLETENESS.")
    print(f"TOOL CONTEXT: Nuclei={tools_status['nuclei']}, SQLMap={tools_status['sqlmap']}, WPScan={tools_status['wpscan']}, Nmap={tools_status['nmap']}")

    print("\n# --- CORE PHILOSOPHY (SLOW, STEADY, SMART) ---")
    print("1. **SEQUENTIAL PROCESSING**: Process the queue strictly one-by-one. No multi-threading (to ensure stability).")
    print("2. **TOOL DISCIPLINE**: Use exact flags defined below. If a tool is missing -> You MUST generate a Native Python function as fallback.")
    print("3. **RESULT CLASSIFICATION**: You MUST use these exact statuses:")
    print("   - 'CONFIRMED_PRESENT': Vulnerability or config exists.")
    print("   - 'REPRODUCED': Attack condition observed (e.g., SQLi/XSS).")
    print("   - 'CHECKED_NO_EXPLOIT': Tested safely, not vulnerable.")
    print("   - 'NOT_REPRODUCED': Condition could not be observed.")
    print("   - 'ERROR': Tool failure.")

    print("\n# --- THE DECISION MATRIX (6 LAYERS OF DEFENSE) ---")

    print("\n[LAYER 1] THE SNIPER (Nuclei - For Known CVEs & Configs)")
    print("   -> TRIGGER: Finding has 'CVE-xxxx' OR keywords (git, env, swagger, config, exposed).")
    print(f"   -> CHECK: If `Nuclei` is installed (Current: {tools_status['nuclei']}).")
    print("   -> COMMAND: `nuclei -u {{TARGET_URL}} -id [CVE_ID] -silent` (if CVE) OR `nuclei -u {{TARGET_URL}} -tags [keyword] -silent`.")
    print("   -> RESULT: If output found -> 'CONFIRMED_PRESENT'. Else -> Layer 3.")

    print("\n[LAYER 2] THE HEAVY ARTILLERY (Injection & CMS)")
    print("   -> TRIGGER: Keywords 'SQL', 'Injection', 'WordPress', 'Joomla'.")
    print(f"   -> CHECK: If `sqlmap` or `wpscan` is installed.")
    print("   -> SQLMAP FLAGS: `sqlmap -u {{TARGET_URL}} --batch --random-agent --level 1 --risk 1`")
    print("   -> WPSCAN FLAGS: `wpscan --url {{TARGET_URL}} --no-update --enumerate p`")
    print("   -> RESULT: If vulnerable -> 'REPRODUCED'. Else -> 'CHECKED_NO_EXPLOIT'.")
    print("   -> FALLBACK: Write Python `requests` function to inject payloads (`' OR 1=1`, `<script>`) and analyze response diff.")

    print("\n[LAYER 3] THE WEB SURGEON (Native Python - Headers & Logic)")
    print("   -> TRIGGER: ZAP findings (CSP, Cache, HSTS, 403, Path Traversal, User-Agent, Cookie).")
    print("   -> ACTION: Write CUSTOM PYTHON CODE using `requests`. use `{{TARGET_URL}}`.")
    print("   -> LOGIC A (Headers): Inspect `response.headers`. Fail if key missing -> 'CONFIRMED_PRESENT'.")
    print("   -> LOGIC B (403 Bypass): Try headers `{'X-Forwarded-For': '127.0.0.1'}`. If 200 OK -> 'REPRODUCED'.")
    print("   -> LOGIC C (Path Traversal): Request `{{TARGET_URL}}/../../etc/passwd` or `boot.ini`.")

    print("\n[LAYER 4] THE INFRA ENGINEER (Nmap - Standard Infra)")
    print("   -> TRIGGER: Keywords 'SSH', 'SSL', 'TLS', 'Apache', 'Nginx', 'EOL', 'Algorithm', 'Port'.")
    print("   -> MANDATORY FLAGS: `nmap -sV -Pn -p [PORT] --script [SCRIPT] {{TARGET_HOST}}`")
    print("   -> MAPPING: SSH=`ssh2-enum-algos`, SSL=`ssl-enum-ciphers`, EOL=`vulners`.")
    print("   -> RESULT: If script output confirms issue -> 'CONFIRMED_PRESENT'.")

    print("\n[LAYER 5] THE UNIVERSAL PROTOCOL ADAPTER (For \"The Unknown\")")
    print("   -> CONTEXT: Findings that don't fit Layers 1-4 (e.g., \"Redis\", \"MongoDB\", \"Memcached\", \"Unknown Service\").")
    print("   -> STRATEGY: DYNAMIC PYTHON SOCKET ANALYSIS.")
    print("   -> INSTRUCTION:")
    print("      1. Analyze 'finding_name' to identify the likely service/port (e.g., Redis -> 6379, Mongo -> 27017).")
    print("      2. Write a Python function using `socket` to connect to that port on `{{TARGET_HOST}}`.")
    print("      3. Send a generic command (e.g., `INFO\\r\\n` for Redis, or just wait for Banner).")
    print("      4. IF connection successful AND banner received -> Mark 'CONFIRMED_PRESENT'.")

    print("\n[LAYER 6] THE SAFETY NET (Last Resort)")
    print("   -> CONTEXT: If absolutely no logic matches and protocol is unknown.")
    print("   -> ACTION: Perform a TCP Connect Check using Python `socket` on the specific port.")
    print("   -> LOGIC: If Connected -> Mark 'CHECKED_NO_EXPLOIT' (Service Active). If Refused -> Mark 'NOT_REPRODUCED'.")

    print("\n# --- EXECUTION PLAN (ACT) ---")
    print("WRITE a Python script 'scripts/verify_vulns.py' that:")
    
    # --- PHẦN CHUẨN HÓA URL (CRITICAL) ---
    print(f"1. **GLOBAL TARGET & NORMALIZATION**:")
    print(f"   - Input Target: '{target_url}'")
    print("   - You MUST implement URL normalization at the start of the script:")
    print("     - `TARGET_URL`: Must start with 'http://' or 'https://' (Use for Web Tools/Requests).")
    print("     - `TARGET_HOST`: Must be IP or Domain ONLY (Strip 'http://', Use for Nmap/Socket).")
    print("     - Example: If input is 'http://scanme.nmap.org', then TARGET_HOST='scanme.nmap.org'.")

    print("2. **STRICT LOOP**: `for index, row in df.iterrows():`")
    print("3. **INTELLIGENT PARSER**:")
    print("   - Inside the loop, write a Python function `analyze_row(row)` that implements the 6 Layers above.")
    print("   - Use `if/elif` logic based on `row['finding_name']` and `row['description']`.")
    print("4. **ERROR PROOFING**: Wrap ONLY the verification logic in `try...except`. If error, Log it and `continue`.")
    print("5. **PERSISTENCE**: Save CSV after **EVERY SINGLE ROW**.")
    print("6. **EVIDENCE**: You MUST capture the FULL STDOUT or HTTP RESPONSE BODY in the 'agent_evidence' column.")

    print("\nFINALLY: Run the script.")
    print(f"7. FINISH: Run '{agent_py_cmd} {s_export}'")
    print(f"{C.CYAN}--------------------------------------------------{C.END}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    check_directories()
    
    # Kiểm tra Tool ngay từ đầu
    missing_tools = check_external_tools()

    print(f"{C.HEADER}{C.BOLD}🛡️   SECURITY PIPELINE V10 (FINAL)   🛡️{C.END}")
    
    try:
        while True:
            print(f"\n1. Start Scan\n2. Process Only\n3. Exit")
            c = input(f"👉 Option: ").strip()
            if c == '1':
                u = run_scanning_phase()
                if u:
                    run_processing_phase()
                    run_bridge_phase(u, missing_tools)
                break
            elif c == '2':
                u = input("👉 Target URL: ").strip()
                run_processing_phase()
                run_bridge_phase(u, missing_tools)
                break
            elif c == '3': sys.exit(0)
    except KeyboardInterrupt: sys.exit(0)

if __name__ == "__main__":
    main()
