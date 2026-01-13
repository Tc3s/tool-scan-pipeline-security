#!/usr/bin/env python3

"""
🎯 MITRE ATT&CK + ZAP Vulnerability Scanner
(Features: Auto Venv + Tool Check + INFINITY AGENT PROMPT)
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
    tools = ["curl", "nmap", "sqlmap", "nikto"]
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

# ============== PHASE 1: SCANNING ==============
def run_scanning_phase():
    Debugger.step("PHASE 1: ACTIVE SCANNING")
    try: subprocess.run("docker --version", shell=True, check=True, stdout=subprocess.DEVNULL)
    except: Debugger.error("Docker missing!"); sys.exit(1)

    print(f"\n{C.HEADER}--- TARGET CONFIG ---{C.END}")
    url = input(f"{C.BOLD}👉 Target URL (Default: http://scanme.nmap.org): {C.END}").strip() or "http://scanme.nmap.org"
    if not url.startswith("http"): url = "http://" + url
    
    print(f"\n{C.CYAN}[ SCAN MODES ]{C.END}")
    print("1. ⚡ Quick Baseline Scan")
    print("2. 🐢 Full Deep Scan (Recommended)")
    print("3. 🕷️ AJAX Spider Scan")
    
    choice = input(f"{C.BOLD}👉 Option (1-3): {C.END}").strip()
    script = "zap-baseline.py"; params = ""
    if choice == '2': script = "zap-full-scan.py"
    elif choice == '3': params = "-j"

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

# ============== PHASE 3: AGENT BRIDGE (INFINITY PROMPT) ==============
def run_bridge_phase(target_url, missing_tools=[]):
    Debugger.step("PHASE 3: AGENT HANDOFF")
    
    py = get_python_exec()
    s_bridge = os.path.join("scripts", "antigravity_agent_bridge.py")
    s_export = os.path.join("scripts", "export_excel.py")
    
    run_cmd(f"\"{py}\" {s_bridge}")
    
    # Tính toán đường dẫn Python cho Agent
    try:
        rel_py = os.path.relpath(py, os.getcwd())
        agent_py_cmd = f"./{rel_py}" if not rel_py.startswith("..") and os.name != 'nt' else py
    except: agent_py_cmd = py

    # --- TẠO GHI CHÚ VỀ TOOL THIẾU ---
    tool_warning = ""
    if missing_tools:
        tool_warning = f"WARNING: MISSING TOOLS ({', '.join(missing_tools)}). YOU MUST USE PYTHON SCRIPTS."

    print("\n" + "="*65)
    print(f"{C.HEADER}{C.BOLD}🚀  PIPELINE COMPLETED - INFINITY AGENT PROMPT READY  🚀{C.END}")
    print("="*65)
    print(f"✅ Data ready at: data/output/vuln_validation_queue.csv")
    print(f"\n{C.YELLOW}👉 COPY THE PROMPT BELOW TO ANTIGRAVITY IDE:{C.END}")
    
    # --- PROMPT VÔ CỰC (INFINITY PROMPT) ---
    print(f"{C.CYAN}--------------------------------------------------{C.END}")
    print(f"You are an Elite Security Research Agent. Target: {target_url}")
    print(f"Mission: Verify findings in 'data/output/vuln_validation_queue.csv' autonomously.")
    
    if tool_warning:
        print(f"{C.RED}{C.BOLD}{tool_warning}{C.END}")

    print("\nEXECUTION FRAMEWORK (The OODA Loop):")
    print("1. OBSERVE (Input): Read the CSV. Identify 'finding_name', 'cve', and 'url_or_port'.")
    
    print(f"\n2. ORIENT (Classify & Plan): Apply this Logic Matrix:")
    
    print(f"   {C.CYAN}[TYPE A] CVE-BASED (e.g., RegreSSHion, Heartbleed){C.END}")
    print("      -> STRATEGY: Use Nmap NSE scripts or known Exploit payloads.")
    print("      -> COMMAND: nmap -sV -p [port] --script [vuln_id] [target]")
    
    print(f"   {C.CYAN}[TYPE B] WEB LOGIC (e.g., Bypass 403, Headers){C.END}")
    print("      -> STRATEGY: Manipulate HTTP Headers (X-Forwarded-For, User-Agent).")
    print("      -> COMMAND: curl -I -H 'X-Forwarded-For: 127.0.0.1' [url]")
    
    print(f"   {C.CYAN}[TYPE C] INFRASTRUCTURE (e.g., EOL OS, 'general/tcp'){C.END}")
    print("      -> STRATEGY: OS Fingerprinting. If port is 'general', scan top ports.")
    print("      -> COMMAND: nmap -O -sV --top-ports 100 [target_ip]")
    
    print(f"   {C.CYAN}[TYPE D] FALLBACK (No Tools / Logic Bugs){C.END}")
    print("      -> STRATEGY: WRITE PYTHON CODE. Do not fail if CLI tools are missing.")
    print("      -> ACTION: Use 'requests', 'socket' to simulate the check.")
    
    print("\n3. ACT (Execute): Run the command/script in the Terminal.")
    
    print("\n4. REPORT (Update CSV):")
    print("   - 'agent_status': 'VERIFIED' | 'CHECKED' | 'ERROR'")
    print("   - 'agent_command': The Command/Script used.")
    print("   - 'agent_evidence': Capture the Output.")
    
    print(f"\n5. FINISH: Save CSV & Run '{agent_py_cmd} {s_export}'")
    print(f"{C.CYAN}--------------------------------------------------{C.END}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    check_directories()
    
    # Kiểm tra Tool ngay từ đầu
    missing_tools = check_external_tools()

    print(f"{C.HEADER}{C.BOLD}🛡️   SECURITY PIPELINE V11 (INFINITY)   🛡️{C.END}")
    
    try:
        while True:
            print(f"\n1. Start Scan\n2. Process Only\n3. Exit")
            c = input(f"👉 Option: ").strip()
            if c == '1':
                u = run_scanning_phase()
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
