#!/usr/bin/env python3

"""
🎯 MITRE ATT&CK + ZAP Vulnerability Scanner
(Features: ZAP Docker + Threat Intelligence + EPSS Scoring + Fast Exploit Check)
"""

import os
import sys
import subprocess
import time
import logging
import logging.handlers
import traceback
import shutil
import glob
import shlex
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse

# Threat Intelligence Modules
try:
    from scripts.enrich_epss import get_epss_score, enrich_dataframe_with_epss, get_epss_scores_batch
    from scripts.exploit_matcher import check_exploit_maturity
    from scripts.calculate_risk_priority import calculate_risk_priority
except ImportError:
    # Fallback for direct execution
    from enrich_epss import get_epss_score, enrich_dataframe_with_epss, get_epss_scores_batch
    from exploit_matcher import check_exploit_maturity
    from calculate_risk_priority import calculate_risk_priority

# ============== CẤU HÌNH HỆ THỐNG ĐỘNG (Project Root) ==============
# Tự động tìm thư mục gốc của project dựa trên vị trí của script này (nằm trong scripts/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
RAW_DIR = os.path.join(DATA_DIR, "raw")
JSON_REPORT = os.path.join(RAW_DIR, "zap_report.json")
HTML_REPORT = os.path.join(RAW_DIR, "zap_report.html")
LOG_FILE = os.path.join(PROJECT_ROOT, "pipeline.log")

# ============== TIMEOUT & RESOURCE LIMITS ==============
MAX_ZAP_SCAN_SECONDS = 12 * 3600         # 12 tiếng tối đa cho subprocess (safety net)
DOCKER_MEMORY_LIMIT = "6g"                # RAM limit cho Docker container (ZAP cần nhiều RAM cho full scan)

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

# Log rotation: giữ 5 file log cũ, mỗi file tối đa 5MB
_log_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.basicConfig(level=logging.DEBUG, handlers=[_log_handler])

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
    @staticmethod
    def debug(msg): print(f"  {C.CYAN}│ {msg}{C.END}"); logging.debug(msg)

# ============== HÀM HỖ TRỢ ==============

def get_python_exec():
    return sys.executable

def find_latest_openvas_xml(raw_dir=None):
    """Tìm file OpenVAS XML mới nhất trong thư mục data/raw/ dựa trên modification time.
    
    Returns:
        str: Đường dẫn tới file XML mới nhất, hoặc None nếu không tìm thấy.
    """
    if raw_dir is None:
        raw_dir = RAW_DIR
    
    xml_files = glob.glob(os.path.join(raw_dir, "*.xml"))
    
    if not xml_files:
        return None
    
    # Sắp xếp theo modification time, file mới nhất đứng đầu
    latest = max(xml_files, key=os.path.getmtime)
    Debugger.info(f"Auto-detected OpenVAS XML: {os.path.basename(latest)} (modified: {datetime.fromtimestamp(os.path.getmtime(latest)).strftime('%Y-%m-%d %H:%M:%S')})")
    return latest

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

def _make_result(returncode, stdout_text):
    """Tạo object giống subprocess.CompletedProcess để các hàm khác dùng."""
    class CmdResult:
        def __init__(self, rc, out):
            self.returncode = rc
            self.stdout = out
    return CmdResult(returncode, stdout_text)

def run_cmd(command, ignore_error=False, timeout=None):
    """Run command với REAL-TIME output streaming.
    
    Output hiện ra terminal NGAY LẬP TỨC (từng dòng) và đồng thời
    ghi vào pipeline.log. Không buffer — bạn thấy ZAP/Nmap/v.v. chạy live.
    
    Args:
        command: Command string or list
        ignore_error: If True, don't exit on non-zero exit code
        timeout: Max seconds to wait. None = no limit.
    
    Returns:
        Result object with .returncode and .stdout, or None on error
    """
    if isinstance(command, str):
        cmd_list = shlex.split(command)
    else:
        cmd_list = command
    Debugger.info(f"Exec: {' '.join(cmd_list)}")
    if timeout:
        Debugger.info(f"Timeout safety net: {timeout}s ({timeout/3600:.1f}h)")
    
    start = time.time()
    collected_output = []
    
    try:
        # Dùng Popen để stream output real-time
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # Line-buffered
        )
        
        # Đọc từng dòng real-time
        while True:
            # Check timeout
            if timeout and (time.time() - start) > timeout:
                proc.kill()
                proc.wait()
                duration = time.time() - start
                Debugger.warning(f"Command TIMED OUT after {duration:.0f}s ({duration/3600:.1f}h)")
                if not ignore_error:
                    Debugger.error("Timeout is fatal. Exiting.")
                    sys.exit(1)
                return _make_result(-1, '\n'.join(collected_output))
            
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break  # Process kết thúc
            
            if line:
                line_clean = line.rstrip('\n\r')
                # In ra terminal NGAY
                print(f"  {C.CYAN}│{C.END} {line_clean}")
                # Ghi vào log file
                logging.debug(line_clean)
                collected_output.append(line_clean)
        
        # Đọc output còn sót lại
        remaining = proc.stdout.read()
        if remaining:
            for extra_line in remaining.splitlines():
                print(f"  {C.CYAN}│{C.END} {extra_line}")
                logging.debug(extra_line)
                collected_output.append(extra_line)
        
        proc.wait()
        returncode = proc.returncode
        duration = time.time() - start
        
        if returncode == 0:
            Debugger.success(f"Completed in {duration:.2f}s (exit=0)")
        elif ignore_error:
            Debugger.warning(f"Completed in {duration:.2f}s (exit={returncode}, ignored)")
        else:
            Debugger.error(f"Command failed after {duration:.2f}s (exit={returncode})")
            sys.exit(1)
        
        return _make_result(returncode, '\n'.join(collected_output))
        
    except FileNotFoundError:
        Debugger.error(f"Command not found: {cmd_list[0]}")
        if not ignore_error:
            sys.exit(1)
        return None
    except Exception as e:
        duration = time.time() - start
        Debugger.error(f"Unexpected error after {duration:.2f}s: {e}")
        logging.exception("run_cmd exception")
        if not ignore_error:
            sys.exit(1)
        return None

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
            uid = str(os.getuid())
            gid = str(os.getgid())
            subprocess.run(["chown", "-R", f"{uid}:{gid}", "data/"],
                           stderr=subprocess.DEVNULL, timeout=10)
            Debugger.success("Permissions fixed.")
        except (subprocess.SubprocessError, OSError) as e:
            Debugger.warning(f"Permission fix skipped: {e}")

# ============== PHASE 1: SCANNING (ZAP ONLY) ==============
def run_scanning_phase():
    Debugger.step("PHASE 1: ACTIVE SCANNING (ZAP)")
    
    # Check Docker
    try:
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        Debugger.error("Docker missing! Cannot run ZAP.")
        sys.exit(1)

    # Pull ZAP Docker image to ensure it's available and up-to-date
    Debugger.info(f"Checking/Pulling ZAP Docker image: {ZAP_IMAGE}")
    try:
        subprocess.run(["docker", "pull", ZAP_IMAGE], check=True)
    except subprocess.CalledProcessError as e:
        Debugger.warning(f"Failed to pull {ZAP_IMAGE}. Will attempt to use local cache if available.")

    print(f"\n{C.HEADER}--- TARGET CONFIG ---{C.END}")
    url = input(f"{C.BOLD}👉 Target URL (Default: http://scanme.nmap.org): {C.END}").strip() or "http://scanme.nmap.org"
    if not url.startswith("http"): url = "http://" + url
    
    # Validate URL (chống command injection)
    parsed = urlparse(url)
    if not parsed.hostname or any(c in url for c in [';', '|', '&', '$', '`', '\n']):
        Debugger.error(f"Invalid URL detected: {url}")
        sys.exit(1)

    # ============== ENGAGEMENT TYPE SELECTION ==============
    print(f"\n{C.HEADER}{C.BOLD}[ ENGAGEMENT TYPE ]{C.END}")
    print(f"  {C.RED}1. 🏴‍☠️ BLACKBOX PENTEST{C.END} — Unauthenticated, Full Exploit Power")
    print(f"  {C.GREEN}2. 🛡️  GREYBOX AUDITOR{C.END}  — Authenticated, Production-Safe")
    engagement_choice = input(f"{C.BOLD}👉 Choose Engagement Type (1-2, Default: 1): {C.END}").strip() or '1'

    scan_context = {'mode': 'BLACKBOX', 'cookie': None}
    if engagement_choice == '2':
        scan_context['mode'] = 'GREYBOX'
        print(f"\n{C.GREEN}🛡️  GREYBOX AUDITOR MODE ACTIVATED{C.END}")
        print(f"   {C.CYAN}ℹ️  Chế độ này yêu cầu Session Cookie/Token để quét xuyên thấu màn hình đăng nhập.{C.END}")
        print(f"   {C.CYAN}ℹ️  SQLMap sẽ chạy ở chế độ an toàn (risk=1) để bảo vệ dữ liệu Production.{C.END}")
        auth_cookie = input(f"{C.BOLD}👉 Session Cookie (VD: PHPSESSID=abc123; token=xyz): {C.END}").strip()
        if auth_cookie:
            scan_context['cookie'] = auth_cookie
            Debugger.success(f"Cookie đã lưu: {auth_cookie[:30]}...")
        else:
            Debugger.warning("Không có Cookie. ZAP sẽ quét Unauthenticated nhưng Agent vẫn chạy ở chế độ Production-Safe.")
    else:
        print(f"\n{C.RED}🏴‍☠️  BLACKBOX PENTEST MODE — Full firepower enabled.{C.END}")

    print(f"\n{C.CYAN}[ ZAP SCAN MODES ]{C.END}")
    print("1. ⚡ Quick Baseline Scan")
    print("2. 🐢 Full Deep Scan (Recommended)")
    print("3. 🕷️ AJAX Spider Scan")
    
    choice = input(f"{C.BOLD}👉 Option (1-3): {C.END}").strip()
    script = "zap-baseline.py"; params = ""
    if choice == '2': script = "zap-full-scan.py"
    elif choice == '3': params = "-j"

    # Xóa report cũ
    for old_report in [JSON_REPORT, HTML_REPORT]:
        try:
            if os.path.exists(old_report):
                os.remove(old_report)
        except OSError as e:
            Debugger.warning(f"Could not remove {old_report}: {e}")

    cwd = os.getcwd()
    uid = str(os.getuid()) if os.name != 'nt' else '0'
    gid = str(os.getgid()) if os.name != 'nt' else '0'
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "--memory", DOCKER_MEMORY_LIMIT,       # RAM limit
        "--memory-swap", DOCKER_MEMORY_LIMIT,   # Không swap
        "--shm-size", "2g",                    # Tăng shm_size chống crash trình duyệt (Firefox/Chrome) khi quét DOM XSS
        "-u", f"{uid}:{gid}",  # User hiện tại, KHÔNG dùng root (-u 0)
        "-v", f"{cwd}/data/raw:/zap/wrk/:rw",
        "-t", ZAP_IMAGE, script,
        "-t", url, "-J", "zap_report.json", "-r", "zap_report.html",
    ]

    # === GREYBOX: Inject Cookie vào ZAP qua Replacer config ===
    if scan_context['mode'] == 'GREYBOX' and scan_context.get('cookie'):
        cookie_val = scan_context['cookie']
        cmd.extend([
            "-config", "replacer.full_list(0).description=auth_cookie",
            "-config", "replacer.full_list(0).enabled=true",
            "-config", "replacer.full_list(0).matchtype=REQ_HEADER",
            "-config", "replacer.full_list(0).matchstr=Cookie",
            "-config", "replacer.full_list(0).regex=false",
            "-config", f"replacer.full_list(0).replacement={cookie_val}",
        ])
        Debugger.success("ZAP Replacer: Cookie Auth Header đã được inject vào mọi request.")
    
    if params:
        cmd.append(params)
    
    # =============================================
    # ZAP EXIT CODES (quan trọng!):
    #   0 = Scan pass, không có alert
    #   1 = Scan xong, có WARN alerts     → THÀNH CÔNG (tìm thấy vulns!)
    #   2 = Scan xong, có FAIL alerts     → THÀNH CÔNG (tìm thấy vulns!)
    #   3 = ZAP gặp lỗi nội bộ           → Vẫn có thể tạo report
    # → Exit code 1,2 là KẾT QUẢ MONG MUỐN cho security scanner!
    # =============================================
    
    Debugger.info(f"ZAP Full Scan starting... (timeout safety net: {MAX_ZAP_SCAN_SECONDS/3600:.0f}h)")
    Debugger.info(f"Docker memory limit: {DOCKER_MEMORY_LIMIT}")
    Debugger.info(f"Engagement Mode: {scan_context['mode']}")
    Debugger.info("ZAP will run until completion. This may take several hours for full scan.")
    
    scan_start = time.time()
    result = run_cmd(cmd, ignore_error=True, timeout=MAX_ZAP_SCAN_SECONDS)
    scan_duration = time.time() - scan_start
    
    Debugger.info(f"ZAP scan finished after {scan_duration:.0f}s ({scan_duration/3600:.1f} hours)")
    
    # Xử lý exit code thông minh
    if result is not None:
        exit_code = result.returncode
        if exit_code == 0:
            Debugger.success("ZAP scan completed — PASS (no alerts found)")
        elif exit_code == 1:
            Debugger.success(f"ZAP scan completed — found WARN-level alerts (exit={exit_code}). This is NORMAL.")
        elif exit_code == 2:
            Debugger.success(f"ZAP scan completed — found FAIL-level alerts (exit={exit_code}). This is NORMAL.")
        elif exit_code == 3:
            Debugger.warning(f"ZAP reported internal errors (exit=3). Report may still be available.")
        else:
            Debugger.warning(f"ZAP exited with unexpected code {exit_code}.")
    else:
        Debugger.warning("ZAP process timed out or was terminated.")
    
    fix_permissions()

    # --- GRACEFUL REPORT HANDLING ---
    if os.path.exists(JSON_REPORT):
        file_size = os.path.getsize(JSON_REPORT)
        if file_size > 10:
            Debugger.success(f"✅ Report saved: {JSON_REPORT} ({file_size:,} bytes)")
        else:
            Debugger.warning(f"Report file exists but very small ({file_size} bytes). May be incomplete.")
    else:
        Debugger.error("No JSON report generated by ZAP.")
        if os.path.exists(HTML_REPORT):
            Debugger.warning(f"HTML report exists ({os.path.getsize(HTML_REPORT):,} bytes) but JSON missing.")
        Debugger.info("Possible causes:")
        Debugger.info("  • Target unreachable or connection refused")
        Debugger.info("  • Docker container killed (out of memory)")
        Debugger.info("  • Incorrect target URL protocol (http vs https)")
        return None, scan_context  # Không crash — caller xử lý

    # Nhắc nhở về OpenVAS (vì tool này chạy ngoài)
    print(f"\n{C.YELLOW}⚠️  IMPORTANT NOTE FOR OPENVAS:{C.END}")
    print("   Please run OpenVAS manually and save the XML report to:")
    print(f"   👉 {C.BOLD}data/raw/<any_name>.xml{C.END}")
    print(f"   {C.CYAN}ℹ️  Pipeline sẽ tự động chọn file XML mới nhất trong data/raw/{C.END}")
    
    return url, scan_context

# ============== PHASE 2: PROCESSING ==============
def run_processing_phase():
    Debugger.step("PHASE 2: DATA PROCESSING")
    if not os.path.exists(JSON_REPORT): Debugger.error("Missing Report"); return

    py = get_python_exec()
    s_parse_zap = os.path.join(SCRIPTS_DIR, "parse_zap.py")
    s_parse_openvas = os.path.join(SCRIPTS_DIR, "parse_openvas.py")
    s_merge = os.path.join(SCRIPTS_DIR, "merge_vulns.py")
    s_map = os.path.join(SCRIPTS_DIR, "apply_attack_mapping.py")
    s_risk = os.path.join(SCRIPTS_DIR, "calculate_risk_priority.py")

    run_cmd([py, s_parse_zap])
    
    openvas_report = find_latest_openvas_xml(RAW_DIR)
    if openvas_report:
        Debugger.success(f"Found OpenVAS report: {os.path.basename(openvas_report)}")
        run_cmd([py, s_parse_openvas, openvas_report, "data/normalized/openvas_findings.csv"])
    else:
        Debugger.warning("No OpenVAS XML found in data/raw/ — skipping OpenVAS parsing.")
    
    run_cmd([py, s_merge])
    run_cmd([py, s_map])
    run_cmd([py, s_risk])
    
    Debugger.success("Processing Complete.")

# ============== PHASE 3: THREAT INTELLIGENCE + VERIFICATION ==============
def run_threat_intel_phase(target_url, missing_tools=[], scan_context=None):
    """
    Threat Intelligence Phase with Interactive Decision Point
    
    1. Enrich with EPSS scores
    2. Ask user: Active Verification or Fast Scan?
    3. If Fast Scan: Check exploit maturity (no network commands)
    4. Calculate final risk score
    5. Export to Excel
    """
    if scan_context is None:
        scan_context = {'mode': 'BLACKBOX', 'cookie': None}
    Debugger.step("PHASE 3: THREAT INTELLIGENCE ENRICHMENT")
    
    # Data paths
    enriched_file = os.path.join(DATA_DIR, "output", "vuln_attack_enriched.csv")
    queue_file = os.path.join(DATA_DIR, "output", "vuln_validation_queue.csv")
    
    # Load the enriched data
    if not os.path.exists(enriched_file):
        Debugger.error(f"Missing enriched file: {enriched_file}")
        return
    
    try:
        df = pd.read_csv(enriched_file)
        Debugger.success(f"Loaded {len(df)} vulnerabilities")
    except Exception as e:
        Debugger.error(f"Failed to load data: {e}")
        return
    
    # --- STEP 1: EPSS Enrichment ---
    Debugger.info("📡 Fetching EPSS scores for all CVEs...")
    
    # Find CVE column (might be 'cve_id', 'cve', 'CVE', etc.)
    cve_col = None
    for col in ['cve_id', 'cve', 'CVE', 'cve_ids']:
        if col in df.columns:
            cve_col = col
            break
    
    if cve_col:
        # --- BATCH EPSS ENRICHMENT (tránh rate limiting) ---
        all_cves = []
        cve_index_map = {}  # cve -> list of row indices
        
        for idx, row in df.iterrows():
            cve_id = row.get(cve_col, "")
            if pd.notna(cve_id) and str(cve_id).strip().upper().startswith("CVE-"):
                cve_clean = str(cve_id).strip()
                all_cves.append(cve_clean)
                if cve_clean not in cve_index_map:
                    cve_index_map[cve_clean] = []
                cve_index_map[cve_clean].append(idx)
        
        Debugger.info(f"Found {len(all_cves)} CVE IDs to query EPSS ({len(set(all_cves))} unique)")
        
        # Batch query
        batch_results = get_epss_scores_batch(list(set(all_cves)))
        
        # Fill results
        epss_scores = [0.0] * len(df)
        epss_percentiles = [0.0] * len(df)
        
        for idx, row in df.iterrows():
            cve_id = row.get(cve_col, "")
            if pd.notna(cve_id) and str(cve_id).strip() in batch_results:
                cve_clean = str(cve_id).strip()
                score, pct = batch_results[cve_clean]
                epss_scores[idx] = score
                epss_percentiles[idx] = pct
                if score > 0:
                    print(f"   {cve_clean}: EPSS={score:.4f}")
        
        df['epss_score'] = epss_scores
        df['epss_percentile'] = epss_percentiles
        Debugger.success(f"EPSS enrichment complete. {sum(1 for s in epss_scores if s > 0)} CVEs with EPSS data.")
    else:
        Debugger.warning("No CVE column found. Skipping EPSS enrichment.")
        df['epss_score'] = 0.0
        df['epss_percentile'] = 0.0
    
    # Initialize columns
    if 'agent_status' not in df.columns:
        df['agent_status'] = ''
    if 'agent_evidence' not in df.columns:
        df['agent_evidence'] = ''
    if 'exploit_available' not in df.columns:
        df['exploit_available'] = False
    
    # --- STEP 2: Interactive Decision Point ---
    print(f"\n{C.BOLD}{'='*60}{C.END}")
    print(f"{C.HEADER}🔀 VERIFICATION MODE SELECTION{C.END}")
    print(f"{'='*60}")
    print(f"{C.CYAN}[A] Active Verification{C.END} - Use verify_vulns.py (network commands: nmap, curl)")
    print(f"{C.GREEN}[F] Fast Scan{C.END} - Check exploit maturity only (no network commands)")
    print()
    
    choice = input(f"{C.BOLD}[?] Launch Active Verification Agent? (y/n): {C.END}").strip().lower()
    
    if choice in ['y', 'yes', 'a', 'active']:
        # === ACTIVE VERIFICATION MODE ===
        Debugger.step("RUNNING ACTIVE VERIFICATION AGENT")
        
        # Save current state for the agent (already has EPSS data from Step 1)
        df.to_csv(queue_file, index=False)
        
        # Extract hostname for verify_vulns.py
        parsed_target = urlparse(target_url if '://' in target_url else f'http://{target_url}')
        target_host = parsed_target.hostname or target_url
        
        # Check if verify_vulns.py exists
        verify_script = os.path.join(SCRIPTS_DIR, "verify_vulns.py")
        if os.path.exists(verify_script):
            py = get_python_exec()
            run_cmd([py, verify_script, target_host], ignore_error=True)
            
            # Reload data after verification — EPSS data is preserved from Step 1
            if os.path.exists(queue_file):
                df = pd.read_csv(queue_file)
        else:
            # Run bridge script for manual agent handoff
            py = get_python_exec()
            s_bridge = os.path.join(SCRIPTS_DIR, "antigravity_agent_bridge.py")
            run_cmd([py, s_bridge], ignore_error=True)
            
            # Print the original prompt for Antigravity agent
            _print_agent_prompt(target_url, missing_tools, scan_context)
            return  # Exit here - agent will handle the rest
    else:
        # === FAST SCAN MODE ===
        Debugger.step("⚡ RUNNING FAST EXPLOIT CHECK")
        print(f"{C.GREEN}⚡ Running Fast Exploit Check (no network commands)...{C.END}")
        
        for idx, row in df.iterrows():
            cve_id = row.get(cve_col, "") if cve_col else ""
            
            if pd.isna(cve_id) or not str(cve_id).strip():
                # No CVE ID
                df.at[idx, 'agent_status'] = 'SKIPPED_NO_CVE'
                df.at[idx, 'agent_evidence'] = 'No CVE ID available for exploit check'
                df.at[idx, 'exploit_available'] = False
            else:
                cve_id = str(cve_id).strip()
                is_weaponized, source = check_exploit_maturity(cve_id)
                
                if is_weaponized:
                    df.at[idx, 'agent_status'] = 'WEAPONIZED'
                    df.at[idx, 'agent_evidence'] = source
                    df.at[idx, 'exploit_available'] = True
                    print(f"   ⚠️  {cve_id}: WEAPONIZED ({source})")
                else:
                    df.at[idx, 'agent_status'] = 'POTENTIAL'
                    df.at[idx, 'agent_evidence'] = 'No public exploit found'
                    df.at[idx, 'exploit_available'] = False
        
        weaponized_count = len(df[df['agent_status'] == 'WEAPONIZED'])
        Debugger.success(f"Fast Scan complete. Found {weaponized_count} weaponized vulnerabilities.")
    
    # --- STEP 3: Calculate Final Risk Score ---
    Debugger.step("CALCULATING FINAL RISK SCORES")
    
    severity_col = 'severity' if 'severity' in df.columns else 'risk' if 'risk' in df.columns else None
    
    final_scores = []
    priorities = []
    
    for idx, row in df.iterrows():
        severity = row.get(severity_col, 'Unknown') if severity_col else 'Unknown'
        epss = row.get('epss_score', 0.0)
        is_weaponized = row.get('exploit_available', False) or row.get('agent_status', '') == 'WEAPONIZED'
        
        score, priority = calculate_risk_priority(severity, epss_score=epss, is_weaponized=is_weaponized)
        final_scores.append(score)
        priorities.append(priority)
    
    df['risk_score'] = final_scores
    df['priority'] = priorities
    
    # Sort by priority and score
    df.sort_values(by=['priority', 'risk_score'], ascending=[True, False], inplace=True)
    
    # Print summary
    print(f"\n📊 Priority Distribution:")
    print(df['priority'].value_counts().to_string())
    
    # --- STEP 4: Save and Export ---
    df.to_csv(queue_file, index=False)
    Debugger.success(f"Saved to: {queue_file}")
    
    # Export to Excel
    py = get_python_exec()
    s_export = os.path.join(SCRIPTS_DIR, "export_excel.py")
    run_cmd([py, s_export])
    # --- XUẤT JSON CHO SOC ---
    py = get_python_exec()
    s_json = os.path.join(SCRIPTS_DIR, "export_json_soc.py")
    if os.path.exists(s_json):
        run_cmd([py, s_json])
    # -------------------------
    
    # Final summary
    print(f"\n{'='*60}")
    print(f"{C.GREEN}{C.BOLD}✅ PIPELINE COMPLETE{C.END}")
    print(f"{'='*60}")
    print(f"📁 CSV: {queue_file}")
    print(f"📊 Excel: vuln_attack_report.xlsx")
    print(f"🔥 P1 (Critical): {len(df[df['priority'] == 'P1'])} items")
    print(f"⚠️  Weaponized: {len(df[df['agent_status'] == 'WEAPONIZED'])} items")


def _print_agent_prompt(target_url, tools, scan_context=None):
    if scan_context is None:
        scan_context = {'mode': 'BLACKBOX', 'cookie': None}
    
    mode = scan_context.get('mode', 'BLACKBOX')
    auth_cookie = scan_context.get('cookie', '')

    # Lấy trạng thái các công cụ hiện có trên hệ thống
    ts = {t: shutil.which(t) is not None for t in ["nuclei", "sqlmap", "wpscan", "nmap"]}
    py = get_python_exec()
    s_export = os.path.join(SCRIPTS_DIR, "export_excel.py")
    s_json = os.path.join(SCRIPTS_DIR, "export_json_soc.py")

    print("\n" + "="*70)

    if mode == 'GREYBOX':
        # ====================================================================
        # PROMPT GREYBOX AUDITOR (Production-Safe, Authenticated)
        # ====================================================================
        print(f"{C.GREEN}{C.BOLD}🛡️  PROMPT - GREYBOX AUDITOR ENGINE (PRODUCTION-SAFE){C.END}")
        print("="*70)

        print(f"⚠️  YOU ARE IN GREYBOX MODE (PRODUCTION-SAFE). DO NOT CRASH THE TARGET.")
        print(f"You are a Production-Safe Security Auditor – Authenticated, Low-Impact, Exploit-Path Required.")
        print(f"TARGET INPUT: DYNAMIC (via sys.argv[1])")
        print(f"MISSION: Verify EVERY finding in 'data/output/vuln_validation_queue.csv' using AUTHENTICATED requests with LOW-RISK payloads.")
        print(f"NEVER use aggressive/destructive payloads. NEVER attack OS/Infrastructure services directly.")
        print(f"TOOL CONTEXT: Nuclei={ts['nuclei']}, SQLMap={ts['sqlmap']}, WPScan={ts['wpscan']}, Nmap={ts['nmap']}")
        if auth_cookie:
            print(f"AUTH_COOKIE: {auth_cookie}")

        print("\n# --- CORE PHILOSOPHY (PRODUCTION-SAFE AUDIT) ---")
        print("1. **SEQUENTIAL PROCESSING**: One row at a time.")
        print("2. **RESUME**: Skip if 'agent_status' is not empty/NaN/'WAITING'.")
        print("3. **RESULT CLASSIFICATION (PRODUCTION-SAFE)**:")
        print("   - 'REPRODUCED' -> Clear PoC success WITH LOW-RISK payload (nuclei hit, safe SQLi detection, traversal leak).")
        print("   - 'CONFIRMED_PRESENT' -> Vulnerable condition + CLEAR EXPLOIT PATH (e.g. weak cipher confirmed).")
        print("   - 'CONFIRMED_INFRA_NO_EXPLOIT' -> Infrastructure/OS finding from OpenVAS. Trusted by Admin Credential. DO NOT ATTACK.")
        print("   - 'CHECKED_NO_EXPLOIT' -> Tested but NO exploit proof.")
        print("   - 'NOT_REPRODUCED' / 'ERROR'.")
        print("4. **EVIDENCE RULES (CONCISE)**: ONLY include DIRECT proof. Extract the LAST 800 chars (not the first 800) for tools like sqlmap/wpscan to capture actual payloads, skipping the startup banner. No proof = 'CHECKED_NO_EXPLOIT'.")
        print("5. **CVE EXHAUSTIVE LOOP**: LOOP through EVERY CVE one by one using `nuclei -id [CVE]`. Only 'REPRODUCED' if clear sign of exploit.")
        print("6. **CLEAN**: Strip ANSI color codes (Regex: `\\\\x1b\\\\[[0-9;]*[mGKF]`).")

        print("\n# --- INFRASTRUCTURE BYPASS RULE (CRITICAL) ---")
        print("RULE: You are testing a PRODUCTION environment with TRUSTED Admin Credentials.")
        print("If the finding's 'url_or_port' is a raw TCP port (21, 22, 23, 25, 445, 512, 513, 514, 5432, 8787, etc.)")
        print("OR the finding name contains OS/Infra keywords (Samba, OpenSSH, Kernel, vsftpd, ProFTPD, SSL Certificate, TLS, dRuby, rlogin, rexec, PostgreSQL EOL, OS EOL):")
        print("   -> IMMEDIATELY return status='CONFIRMED_INFRA_NO_EXPLOIT', evidence='Trusted Credentialed Admin Data. Skipped to prevent Production disruption.'")
        print("   -> DO NOT run nuclei, nmap, sqlmap, or any network probe on these findings.")
        print("   -> ONLY focus your energy on HTTP/HTTPS Web Application findings.")

        print("\n# --- THE DECISION MATRIX (Production-Safe) ---")

        print("\n[LAYER 0] INFRA SHIELD – Auto-Skip OS/Network Findings")
        print("   -> ACTION: Check if finding is Infrastructure/OS (non-HTTP port or OS-level CVE).")
        print("   -> RESULT: If yes, return 'CONFIRMED_INFRA_NO_EXPLOIT'. Skip ALL subsequent layers.")

        print("\n[LAYER 1] SNIPER – Full CVE Loop with Nuclei (Authenticated)")
        print("   -> ACTION: LOOP ALL CVEs found in column -> Run nuclei one by one.")
        if auth_cookie:
            print(f"   -> MUST USE: nuclei -id [CVE] -target [URL] -H 'Cookie: {auth_cookie}' -et tags:dos,intrusive")
        else:
            print("   -> MUST USE: nuclei -id [CVE] -target [URL] -et tags:dos,intrusive")
        print("   -> NOTE: -et tags:dos,intrusive EXCLUDES destructive templates to protect Production.")
        print("   -> RESULT: ONLY 'REPRODUCED' if output shows clear exploit (matched/leak/[vulnerable]).")

        print("\n[LAYER 2] SAFE ARTILLERY – Low-Risk Injection Proof")
        if auth_cookie:
            print(f"   -> ACTION: sqlmap --level 1 --risk 1 --batch --cookie='{auth_cookie}' --technique=BEU")
        else:
            print("   -> ACTION: sqlmap --level 1 --risk 1 --batch --technique=BEU")
        print("   -> ⚠️  ABSOLUTELY DO NOT use --risk 2 or --risk 3. This is Production!")
        print("   -> --technique=BEU limits to Boolean/Error/Union (NO stacked queries that modify data).")
        print("   -> RESULT: ONLY 'REPRODUCED' if injectable or execution success.")

        print("\n[LAYER 3] WEB SURGEON – Authenticated Exploit-Path Checks")
        print("   -> ACTION: 403 Bypass (Headers), Path Traversal (../../etc/passwd, win.ini, web.xml).")
        if auth_cookie:
            print(f"   -> ALL requests.get/post MUST include headers={{'Cookie': '{auth_cookie}'}}")
        print("   -> MUST test both root path AND parameters (?file=, ?page=, ?path=, ?id=).")
        print("   -> RESULT: ONLY 'REPRODUCED' if leaks sensitive file/content or bypass works.")

        print("\n[LAYER 4] INFRA – DISABLED IN GREYBOX MODE")
        print("   -> All infrastructure scanning is handled by Layer 0 (Auto-Skip).")
        print("   -> Nmap is ONLY used for HTTP service fingerprinting if absolutely needed.")
        print("   -> Use: nmap -sV -Pn --script 'safe' -p [PORT] (safe scripts only).")

        print("\n# --- EXECUTION PLAN (ACT) ---")
        print("WRITE 'scripts/verify_vulns.py':")
        print("1. Normalize target from `sys.argv[1]`.")
        print("2. Loop rows, skip processed, save CSV after EVERY row.")
        print("3. Implement LAYER 0 FIRST: Check if finding is Infra/OS -> auto-skip.")
        print("4. Implement caching: CMD_CACHE and NMAP_CACHE.")
        if auth_cookie:
            print(f"5. HARDCODE session cookie '{auth_cookie}' into ALL HTTP requests and tool commands.")
        else:
            print("5. No cookie provided. Proceed without authentication headers.")
        print("6. implement `check_403_bypass(target)` with 12+ techniques. ALL requests must carry Cookie header.")
        print("7. implement `check_path_traversal(target)` with 22+ payloads. MUST test root path AND parameters (?file=, ?page=, ?id=). ALL requests must carry Cookie header.")
        print("8. analyze_row(row): Layer 0 (Infra Skip) -> Layer 1 (Nuclei) -> Layer 2 (Safe SQLMap) -> Layer 3 (Web Surgeon).")
        print("9. Evidence: Concise proof only. Write a robust `extract_evidence` that scans from the BOTTOM up to capture the final payload/success line, completely ignoring ASCII banners.")

    else:
        # ====================================================================
        # PROMPT BLACKBOX PENTEST V2 — ELITE FULL COVERAGE
        # ====================================================================
        print(f"{C.HEADER}{C.BOLD}🚀 PROMPT - ELITE SECURITY AUDIT ENGINE V2 (FULL COVERAGE){C.END}")
        print("="*70)

        print(f"You are an Elite Security Audit Engine V2 – Strict Proof-Only, Exploit-Path Required, No Version Assumptions.")
        print(f"TARGET INPUT: DYNAMIC (via sys.argv[1])")
        print(f"MISSION: Verify EVERY finding in 'data/output/vuln_validation_queue.csv' with EXTREME FOCUS ON REPRODUCIBLE EXPLOIT PROOF.")
        print(f"NEVER confirm a vulnerability based solely on version detection, banner leak, or vulners listing unless there is CLEAR EXPLOIT PATH or PoC success.")
        print(f"TOOL CONTEXT: Nuclei={ts['nuclei']}, SQLMap={ts['sqlmap']}, WPScan={ts['wpscan']}, Nmap={ts['nmap']}")

        print("\n# --- CORE PHILOSOPHY (PROOF & EXPLOIT-PATH ONLY) ---")
        print("1. **SEQUENTIAL PROCESSING**: One row at a time.")
        print("2. **RESUME**: Skip if 'agent_status' is not empty/NaN/'WAITING'.")
        print("3. **RESULT CLASSIFICATION (VERY STRICT)**:")
        print("   - 'REPRODUCED' -> Clear PoC success (nuclei hit, payload success, traversal leak, 403 bypass -> 200, XSS reflection, SSRF callback).")
        print("   - 'CONFIRMED_PRESENT' -> Vulnerable condition + CLEAR EXPLOIT PATH (e.g. weak cipher + downgrade possible).")
        print("   - 'CHECKED_NO_EXPLOIT' -> Tested but NO exploit proof (only version/banner found, no path).")
        print("   - 'NOT_REPRODUCED' / 'ERROR'.")
        print("4. **EVIDENCE RULES (CONCISE)**: ONLY include DIRECT proof. Extract the LAST 800 chars (not the first 800) for tools like sqlmap/wpscan to capture actual payloads, skipping the startup banner. No proof = 'CHECKED_NO_EXPLOIT'.")
        print("5. **CVE EXHAUSTIVE LOOP**: LOOP through EVERY CVE one by one using `nuclei -id [CVE]`. Only 'REPRODUCED' if clear sign of exploit.")
        print("6. **CLEAN**: Strip ANSI color codes (Regex: `\\\\\\\\x1b\\\\\\\\[[0-9;]*[mGKF]`).")

        print("\n# --- SMART URL EXTRACTION RULE (CRITICAL) ---")
        print("When building the target URL for injection tools (sqlmap, XSS, SSRF):")
        print("  - Check the 'description' and 'url_or_port' columns for FULL URLs with parameters (e.g., /page.php?id=1).")
        print("  - If found, use THAT specific URL as the injection target, NOT the bare root domain.")
        print("  - If only a port number is given, construct http://TARGET_IP:PORT/ and spider for injectable endpoints first.")
        print("  - For phpMyAdmin findings: target http://TARGET_IP/phpmyadmin/ or http://TARGET_IP/phpMyAdmin/.")

        print("\n# --- RETRY & FALLBACK LOGIC ---")
        print("  - If any tool returns 'TIMEOUT': Retry ONCE with 2x timeout.")
        print("  - If 'connection refused': Try switching http <-> https, or try the other common ports (80, 443, 8080, 8443).")
        print("  - If tool binary not found: Use Python `requests` library as fallback for HTTP-based checks.")

        print("\n# --- THE DECISION MATRIX (8-Layer Full Coverage) ---")

        print("\n[LAYER 1] SNIPER – Full CVE Loop with Nuclei")
        print("   -> ACTION: LOOP ALL CVEs found in column -> Run nuclei one by one.")
        print("   -> If nuclei TIMEOUT: retry once with timeout=120.")
        print("   -> RESULT: ONLY 'REPRODUCED' if output shows clear exploit (matched/leak/[vulnerable]).")

        print("\n[LAYER 2A] HEAVY ARTILLERY – SQL Injection Proof")
        print("   -> TRIGGER: finding_name OR description contains 'sql', 'injection', 'query', 'database'.")
        print("   -> ACTION: Extract the FULL URL with parameters from the CSV row (description/url_or_port). If no params found, try common endpoints: /index.php?id=1, /login.php?user=test, /page.php?id=1.")
        print("   -> COMMAND: sqlmap -u '[FULL_URL_WITH_PARAMS]' --level 3 --risk 3 --batch --forms --crawl=2")
        print("   -> NOTE: --forms makes sqlmap auto-discover HTML forms. --crawl=2 finds nearby injectable pages.")
        print("   -> FALLBACK: wpscan --url [URL] --enumerate vp,vt,tt,u (if 'wordpress' in description).")
        print("   -> RESULT: ONLY 'REPRODUCED' if 'is vulnerable' or 'injectable' appears in output.")

        print("\n[LAYER 2B] XSS HUNTER – Cross-Site Scripting Proof")
        print("   -> TRIGGER: finding_name OR description contains 'xss', 'cross-site', 'scripting', 'reflected', 'stored'.")
        print("   -> ACTION: Extract the target URL. Test these payloads via Python requests on ALL discovered parameters:")
        print("      Payloads: '<script>alert(1)</script>', '\"><img src=x onerror=alert(1)>', '{{7*7}}', '<svg/onload=alert(1)>', 'javascript:alert(1)'")
        print("   -> Check if the EXACT payload string is REFLECTED UNENCODED in the HTTP response body.")
        print("   -> Also run: nuclei -tags xss -target [URL] (uses nuclei's built-in XSS templates).")
        print("   -> RESULT: 'REPRODUCED' ONLY if payload is reflected without HTML encoding in response.")

        print("\n[LAYER 3A] WEB SURGEON – 403 Bypass & Path Traversal")
        print("   -> ACTION: 403 Bypass (12+ Headers), Path Traversal (22+ payloads).")
        print("   -> APACHE FALLBACK: Try PoC for CVE-2021-41773 style path traversal.")
        print("   -> MUST test both root path AND parameters (?file=, ?page=, ?path=, ?include=, ?template=, ?id=).")
        print("   -> RESULT: ONLY 'REPRODUCED' if leaks sensitive file/content (root:x:0:0, [extensions], <web-app>) or bypass works.")

        print("\n[LAYER 3B] SSRF PROBE – Server-Side Request Forgery")
        print("   -> TRIGGER: finding_name OR description contains 'ssrf', 'request forgery', 'url', 'redirect', 'proxy', 'fetch'.")
        print("   -> ACTION: Use Python requests to inject these SSRF payloads into URL-type parameters (?url=, ?redirect=, ?next=, ?dest=, ?uri=, ?path=):")
        print("      - http://127.0.0.1:80/, http://localhost/, http://[::1]/, http://0x7f000001/")
        print("      - http://169.254.169.254/latest/meta-data/ (AWS metadata)")
        print("      - file:///etc/passwd")
        print("   -> Check response for: 'root:x:0:0', 'ami-id', 'instance-id', localhost HTML content, or status 200 with body length change.")
        print("   -> RESULT: 'REPRODUCED' if response leaks internal data or metadata.")

        print("\n[LAYER 4] INFRA – Nmap with Exploit-Path Requirement")
        print("   -> ACTION: nmap -sV -Pn -p [PORT] --script vulners,ssh2-enum-algos,ssl-enum-ciphers.")
        print("   -> RESULT: ONLY 'CONFIRMED_PRESENT' if weak config + CLEAR EXPLOIT PATH (e.g. downgrade possible).")
        print("   -> Default vulners version match alone = 'CHECKED_NO_EXPLOIT'.")

        print("\n[LAYER 5] PROTOCOL SPECIALIST – Service-Specific PoC")
        print("   -> TRIGGER: finding involves non-HTTP service (FTP, SSH, SMB, RMI, dRuby, rlogin, rexec).")
        print("   -> ACTION (per service):")
        print("      - vsftpd (port 21): Use Python socket to connect, send username ending with ':)' (smiley backdoor CVE-2011-2523). Check if port 6200 opens.")
        print("      - ProFTPD (port 21): Send 'HELP' command via socket, parse banner for vulnerable version + try SITE CPFR/CPTO for arbitrary file copy.")
        print("      - rlogin (port 513): Use Python socket, try rlogin with '-froot' to test passwordless root login.")
        print("      - rexec (port 512): Use Python socket, try connecting with common creds (root:root, root:<empty>).")
        print("      - dRuby (port 8787): Use Python socket to send DRb protocol probe. Check if it accepts method calls.")
        print("      - SMB/Samba (port 445): Try 'smbclient -L //TARGET -N' (null session) to list shares without credentials.")
        print("   -> RESULT: 'REPRODUCED' if backdoor/RCE is confirmed. 'CONFIRMED_PRESENT' if service responds to exploit conditions but no shell obtained.")

        print("\n[LAYER 6] DESERIALIZATION & RCE HUNTER")
        print("   -> TRIGGER: finding_name OR description contains 'deseriali', 'unserialize', 'rce', 'remote code', 'command execution', 'code injection', 'object injection'.")
        print("   -> ACTION:")
        print("      - PHP Unserialize: Send crafted serialized PHP object in POST body/Cookie. Check for error messages revealing deserialization attempt.")
        print("      - Java (Tomcat/RMI): Use nuclei -tags rce,java -target [URL]. Also try ysoserial payloads if applicable.")
        print("      - Python pickle: Send base64-encoded pickle payload. Check if server executes os.system() callback.")
        print("   -> FALLBACK: Simple command injection tests: ; id, | id, `id`, $(id) appended to parameters. Check if 'uid=' appears in response.")
        print("   -> RESULT: 'REPRODUCED' if command output or error trace confirms code execution.")

        print("\n[LAYER 7] SAFETY NET – Default Classification")
        print("   -> If ALL above layers fail to produce proof: return 'CHECKED_NO_EXPLOIT'.")
        print("   -> TCP port open alone is NOT vulnerability proof.")

        print("\n# --- EXECUTION PLAN (ACT) ---")
        print("WRITE 'scripts/verify_vulns.py':")
        print("1. Normalize target from `sys.argv[1]`.")
        print("2. Loop rows, skip processed, save CSV after EVERY row.")
        print("3. Implement caching: CMD_CACHE (store ALL command outputs) and NMAP_CACHE (store Nmap output PER PORT).")
        print("4. Implement `extract_injectable_url(row)`: Parse 'description' and 'url_or_port' columns to find FULL URLs with parameters. Fallback to constructing URL from IP+port.")
        print("5. Implement `check_403_bypass(target_url)` with 12+ header techniques + 10+ path mutations.")
        print("6. Implement `check_path_traversal(target_url)` with 22+ payloads. Test BOTH root path AND common parameters (?file=, ?page=, ?include=, ?id=).")
        print("7. Implement `check_xss_reflection(target_url, params)`: Send 5+ XSS payloads per parameter, check if reflected unencoded.")
        print("8. Implement `check_ssrf(target_url, params)`: Send SSRF payloads to URL-type params, check for internal data leak.")
        print("9. Implement `check_service_exploit(target_ip, port, service_name)`: Protocol-specific PoC (vsftpd backdoor, rlogin, smbclient null session, dRuby probe).")
        print("10. Implement `check_deserialization(target_url)`: Command injection tests (; id, | id, `id`, $(id)) + PHP serialized object probe.")
        print("11. analyze_row(row): 8-layer waterfall: Layer 1 (Nuclei) -> 2A (SQLi) -> 2B (XSS) -> 3A (403/LFI) -> 3B (SSRF) -> 4 (Nmap) -> 5 (Protocol PoC) -> 6 (Deser/RCE) -> 7 (Safety Net).")
        print("12. Evidence: Write robust `extract_evidence(text, keyword)` that scans from BOTTOM UP to capture final payload/success line, ignoring ASCII banners.")

    # --- PHẦN CHUNG CHO CẢ 2 MODE ---
    print("\nFINALLY: Run the script.")
    print(f"7. FINISH: Run '{py} {s_export}' then Run '{py} {s_json}'")
    # --- KẾT THÚC NỘI DUNG PROMPT ---

    print(f"{C.CYAN}--------------------------------------------------{C.END}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    check_directories()
    
    # Kiểm tra Tool ngay từ đầu
    missing_tools = check_external_tools()

    print(f"{C.HEADER}{C.BOLD}🛡️   SECURITY PIPELINE (THREAT INTELLIGENCE)   🛡️{C.END}")
    
    try:
        while True:
            print(f"\n1. Start Scan\n2. Process Only\n3. Exit")
            c = input(f"👉 Option: ").strip()
            if c == '1':
                result = run_scanning_phase()
                if result and result[0]:
                    u, scan_context = result
                    run_processing_phase()
                    run_threat_intel_phase(u, missing_tools, scan_context)
                else:
                    Debugger.error("Scanning phase failed. No target URL returned.")
                    Debugger.info("You can try Option 2 (Process Only) if you have existing data.")
                break
            elif c == '2':
                u = input("👉 Target URL: ").strip()
                # Hỏi Engagement Mode cho Process Only
                print(f"\n{C.HEADER}{C.BOLD}[ ENGAGEMENT TYPE ]{C.END}")
                print(f"  {C.RED}1. 🏴‍☠️ BLACKBOX PENTEST{C.END}")
                print(f"  {C.GREEN}2. 🛡️  GREYBOX AUDITOR{C.END}")
                eg = input(f"{C.BOLD}👉 Choose (1-2, Default: 1): {C.END}").strip() or '1'
                scan_context = {'mode': 'BLACKBOX', 'cookie': None}
                if eg == '2':
                    scan_context['mode'] = 'GREYBOX'
                    cookie = input(f"{C.BOLD}👉 Session Cookie (VD: PHPSESSID=abc123): {C.END}").strip()
                    if cookie:
                        scan_context['cookie'] = cookie
                run_processing_phase()
                run_threat_intel_phase(u, missing_tools, scan_context)
                break
            elif c == '3': sys.exit(0)
    except KeyboardInterrupt: sys.exit(0)

if __name__ == "__main__":
    main()
