#!/usr/bin/env python3
import os
import sys
import shutil
import glob
from datetime import datetime

# ============== COLORS ==============
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_step(msg):
    print(f"\n{C.BOLD}{C.BLUE}▶️  {msg}{C.END}")

def print_ok(msg):
    print(f"  {C.GREEN}✅ {msg}{C.END}")

def print_warn(msg):
    print(f"  {C.YELLOW}⚠️  {msg}{C.END}")

def print_fail(msg):
    print(f"  {C.RED}❌ {msg}{C.END}")

def main():
    print(f"{C.HEADER}{C.BOLD}🔍 PROJECT PORTABILITY & PATH CHECKER{C.END}")
    print("="*50)
    
    # 1. Check PROJECT_ROOT
    print_step("Checking Project Root Discovery")
    try:
        # Script is expected to be in project_root/scripts/test_portability.py
        current_script_path = os.path.abspath(__file__)
        root = os.path.dirname(os.path.dirname(current_script_path))
        print_ok(f"Detected ROOT: {root}")
        
        if os.path.basename(root) == "tool-scan-pipeline-security":
            print_ok("Root folder name looks correct.")
        else:
            print_warn(f"Root folder name is '{os.path.basename(root)}', expected 'tool-scan-pipeline-security'. (This is fine if you renamed it)")
    except Exception as e:
        print_fail(f"Failed to detect root: {e}")

    # 2. Check Essential Directories
    print_step("Checking Directory Structure")
    dirs = ["data", "scripts", "mapping", "data/raw", "data/normalized", "data/output"]
    for d in dirs:
        full_path = os.path.join(root, d)
        if os.path.exists(full_path):
            print_ok(f"Found: {d}/")
        else:
            print_fail(f"MISSING: {d}/")

    # 3. Check CLI Tools (Binaries)
    print_step("Checking CLI Tool Binaries (PATH)")
    tools = ["nuclei", "sqlmap", "nmap", "wpscan", "curl", "python3"]
    for t in tools:
        path = shutil.which(t)
        if path:
            print_ok(f"{t:10s}: Found at {path}")
        else:
            print_fail(f"{t:10s}: NOT FOUND in PATH")

    # 4. Check Tool Data (Smart Discovery)
    print_step("Checking Tool Data (Smart Discovery)")
    
    # Metasploit
    print("  Metasploit Modules:")
    msf_candidates = [
        "/opt/metasploit-framework/embedded/framework/modules",
        "/usr/share/metasploit-framework/modules",
        "/usr/lib/metasploit-framework/modules",
        os.path.expanduser("~/.msf4/modules")
    ]
    msf_found = False
    for c in msf_candidates:
        if os.path.exists(c):
            print_ok(f"Found at {c}")
            msf_found = True
            break
    if not msf_found: print_warn("Metasploit modules not found in default locations.")

    # Nuclei Templates
    print("  Nuclei Templates:")
    nuclei_candidates = [
        os.path.expanduser("~/nuclei-templates"),
        "/usr/share/nuclei-templates",
        os.path.join(root, "nuclei-templates")
    ]
    n_found = False
    for c in nuclei_candidates:
        if os.path.exists(c):
            print_ok(f"Found at {c}")
            n_found = True
            break
    if not n_found: print_warn("Nuclei templates not found. Run 'nuclei -ut' to download.")

    # 5. Check Script Consistency
    print_step("Checking Script Accessibility")
    scripts = [
        "run_pipeline.py", "parse_zap.py", "merge_vulns.py", 
        "apply_attack_mapping.py", "calculate_risk_priority.py", 
        "export_excel.py", "export_json_soc.py", "exploit_matcher.py"
    ]
    for s in scripts:
        s_path = os.path.join(root, "scripts", s)
        if os.path.exists(s_path):
            print_ok(f"{s:25s}: Accessible")
        else:
            print_fail(f"{s:25s}: NOT ACCESSIBLE")

    print("\n" + "="*50)
    print(f"{C.BOLD}{C.GREEN}✨ CHECK COMPLETE ✨{C.END}")
    print("If all essential items are green, the project is safely portable.")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
