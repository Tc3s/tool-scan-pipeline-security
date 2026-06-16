#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import importlib.util

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

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True).strip()
    except Exception:
        return None

def main():
    print(f"{C.HEADER}{C.BOLD}🔍 PIPELINE SETUP VERIFICATION SCRIPT{C.END}")
    print("="*60)
    
    all_passed = True

    # 1. Check Directory Structure
    print_step("1. Checking Directory Structure")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dirs = ["data/raw", "data/normalized", "data/output", "mapping", "scripts"]
    for d in dirs:
        path = os.path.join(root, d)
        if os.path.isdir(path):
            print_ok(f"Directory exists: {d}")
        else:
            print_fail(f"Missing directory: {d}")
            all_passed = False

    # 2. Check System Binaries
    print_step("2. Checking Core System Tools")
    core_tools = ["python3", "pip3", "git", "curl", "unzip", "docker"]
    for t in core_tools:
        if shutil.which(t):
            print_ok(f"Found {t}")
        else:
            print_fail(f"Missing core tool: {t}")
            all_passed = False

    # Check Docker Permission
    print_step("3. Checking Docker Permissions")
    out = run_cmd("docker info")
    if out:
        print_ok("Docker daemon is reachable without sudo")
    else:
        print_fail("Cannot connect to Docker daemon. Did you run 'newgrp docker' or logout/login?")
        all_passed = False

    # 3. Check Security Tools
    print_step("4. Checking Security Tool Binaries")
    sec_tools = ["nmap", "sqlmap", "nikto", "wpscan", "nuclei", "searchsploit", "msfconsole"]
    for t in sec_tools:
        if shutil.which(t):
            print_ok(f"Found {t}")
        else:
            print_fail(f"Missing security tool: {t}")
            all_passed = False

    # 4. Check Python Virtual Environment & Packages
    print_step("5. Checking Python Virtual Environment & Packages")
    venv_path = os.path.join(root, "venv")
    if os.path.isdir(venv_path):
        print_ok("Virtual environment folder 'venv' exists")
    else:
        print_fail("Virtual environment 'venv' not found")
        all_passed = False

    # Check if we are running inside venv, or check the venv's python directly
    packages = ["pandas", "requests", "yaml", "openpyxl", "defusedxml"]
    venv_python = os.path.join(venv_path, "bin", "python3")
    if os.path.exists(venv_python):
        for pkg in packages:
            # check via venv python
            check = run_cmd(f"{venv_python} -c \"import {pkg}\"")
            if check is not None:
                print_ok(f"Python package installed: {pkg}")
            else:
                print_fail(f"Python package missing in venv: {pkg}")
                all_passed = False
    else:
        print_fail("Python binary not found inside venv")

    # 5. Check Databases and Tool Resources
    print_step("6. Checking Tool Databases & Resources")
    
    # WPScan DB
    wpscan_dir = os.path.expanduser("~/.wpscan/db")
    if os.path.isdir(wpscan_dir) and len(os.listdir(wpscan_dir)) > 0:
        print_ok("WPScan database is present")
    else:
        print_warn("WPScan database might not be updated. Run 'wpscan --update'")

    # Nmap scripts
    if os.path.exists("/usr/share/nmap/scripts/script.db"):
        print_ok("Nmap script database is present")
    else:
        print_fail("Nmap script database missing")
        all_passed = False

    # Exploit-DB
    if os.path.exists("/opt/exploitdb/files_exploits.csv"):
        print_ok("SearchSploit (Exploit-DB) database is present")
    else:
        print_fail("SearchSploit database missing at /opt/exploitdb")
        all_passed = False

    # Nuclei Templates
    n_found = False
    for p in [os.path.expanduser("~/nuclei-templates"), "/usr/share/nuclei-templates", os.path.join(root, "nuclei-templates")]:
        if os.path.isdir(p):
            print_ok(f"Nuclei templates found at {p}")
            n_found = True
            break
    if not n_found:
        print_warn("Nuclei templates not found. Run 'nuclei -ut'")

    # 6. Check Docker Images
    print_step("7. Checking Docker Images")
    zap_image = "ghcr.io/zaproxy/zaproxy:stable"
    if run_cmd(f"docker images -q {zap_image}"):
        print_ok(f"Docker image found: {zap_image}")
    else:
        print_warn(f"Docker image missing: {zap_image}")
        all_passed = False

    print("\n" + "="*60)
    if all_passed:
        print(f"{C.BOLD}{C.GREEN}🎉 BINGO! ALL TOOLS ARE DOWNLOADED AND SETUP CORRECTLY! 🎉{C.END}")
        print("Your Ubuntu 24.04 environment is fully ready to run the pipeline.")
    else:
        print(f"{C.BOLD}{C.RED}⚠️ SOME CHECKS FAILED!⚠️{C.END}")
        print("Please review the red marks above. You might need to re-run './setup.sh' or fix issues manually.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
