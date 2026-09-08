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
import json
import tempfile
import yaml
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse

# Threat Intelligence Modules
try:
    from scripts import runtime_context as rt
    from scripts.enrich_epss import enrich_dataframe_with_epss
    from scripts.exploit_matcher import check_exploit_maturity_detail
    from scripts.calculate_risk_priority import calculate_risk_for_row
    from scripts.schema_utils import extract_cves, normalize_dataframe_schema, redact_sensitive
except ImportError:
    # Fallback for direct execution
    import runtime_context as rt
    from enrich_epss import enrich_dataframe_with_epss
    from exploit_matcher import check_exploit_maturity_detail
    from calculate_risk_priority import calculate_risk_for_row
    from schema_utils import extract_cves, normalize_dataframe_schema, redact_sensitive

# ============== CẤU HÌNH HỆ THỐNG ĐỘNG (Project Root) ==============
# Tự động tìm thư mục gốc của project dựa trên vị trí của script này (nằm trong scripts/)
PROJECT_ROOT = str(rt.project_root())
SCRIPTS_DIR = str(rt.project_root() / "scripts")

# Các biến phụ thuộc run_dir() phải được khởi tạo LAZY (trong main/hàm)
# để timestamp luôn lấy đúng thời điểm chạy, không bị cache lúc import.
DATA_DIR = None
RAW_DIR = None
JSON_REPORT = None
HTML_REPORT = None
LOG_FILE = None

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def _init_run_paths(reset_session=True):
    """Khởi tạo tất cả đường dẫn phụ thuộc run_dir()."""
    global DATA_DIR, RAW_DIR, JSON_REPORT, HTML_REPORT, LOG_FILE
    if reset_session:
        rt._SESSION_RUN_DIR = None
    DATA_DIR = str(rt.run_dir())
    # QUAN TRỌNG: Export VA_RUN_DIR để tất cả subprocess con (merge_vulns.py,
    # calculate_risk_priority.py, export_excel.py...) dùng CÙNG thư mục run,
    # không tự tạo timestamp mới khi import runtime_context.
    os.environ["VA_RUN_DIR"] = DATA_DIR
    rt.ensure_runtime_dirs()
    RAW_DIR = str(rt.raw_dir())
    JSON_REPORT = os.path.join(RAW_DIR, "zap_report.json")
    HTML_REPORT = os.path.join(RAW_DIR, "zap_report.html")
    LOG_FILE = str(rt.logs_dir() / "pipeline.log")
    # Thiết lập log rotation SAU KHI LOG_FILE đã sẵn sàng
    try:
        _log_handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
        _log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        root_logger = logging.getLogger()
        root_logger.handlers = [_log_handler]
        root_logger.setLevel(logging.DEBUG)
    except Exception:
        pass


def ensure_run_paths():
    """Đảm bảo các biến đường dẫn runtime đã được khởi tạo."""
    if RAW_DIR is None or DATA_DIR is None:
        _init_run_paths(reset_session=False)

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

# Log rotation: được khởi tạo trong _init_run_paths() vì LOG_FILE phụ thuộc run_dir()
logging.basicConfig(level=logging.DEBUG)

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
    ensure_run_paths()
    if raw_dir is None:
        raw_dir = RAW_DIR or str(rt.raw_dir())
    
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
    tools = ["curl", "nmap", "nuclei"]
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
        print(f"   {C.YELLOW}👉 Recommendation: Please install missing tools or ensure they are available in PATH.{C.END}")
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
    display_cmd = " ".join(redact_sensitive(str(part)) for part in cmd_list)
    Debugger.info(f"Exec: {display_cmd}")
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
        if proc.stdout:
            try:
                proc.stdout.close()
            except Exception:
                pass
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

def _java_properties_value(value):
    """Escape a value for a Java .properties file."""
    return str(value).replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")

def write_zap_auth_replacer_config(cookie_value, raw_dir=None):
    """Write a temporary ZAP config file so auth cookies do not appear in process args."""
    if not cookie_value:
        return None
    if "\r" in cookie_value or "\n" in cookie_value:
        raise ValueError("Auth cookie contains CR/LF and was rejected to prevent header injection.")

    if raw_dir is None:
        raw_dir = RAW_DIR or str(rt.raw_dir())
    os.makedirs(raw_dir, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=".zap_auth_", suffix=".properties", dir=raw_dir, text=True)
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("replacer.full_list(0).description=auth_cookie\n")
            handle.write("replacer.full_list(0).enabled=true\n")
            handle.write("replacer.full_list(0).matchtype=REQ_HEADER\n")
            handle.write("replacer.full_list(0).matchstr=Cookie\n")
            handle.write("replacer.full_list(0).regex=false\n")
            handle.write(f"replacer.full_list(0).replacement={_java_properties_value(cookie_value)}\n")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    return path

def zap_container_config_path(host_config_path):
    return f"/zap/wrk/{os.path.basename(host_config_path)}"

def remove_sensitive_temp_file(path):
    if not path:
        return
    try:
        os.remove(path)
        Debugger.info("Removed temporary ZAP auth config file.")
    except OSError as exc:
        Debugger.warning(f"Could not remove temporary ZAP auth config file: {exc}")

def check_directories():
    Debugger.info("Checking directory structure...")
    dirs = [RAW_DIR, str(rt.normalized_dir()), str(rt.output_dir()), SCRIPTS_DIR]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def remove_stale_file(path, reason):
    try:
        if os.path.exists(path):
            os.remove(path)
            Debugger.info(f"Removed stale {os.path.basename(path)} ({reason}).")
    except OSError as exc:
        Debugger.warning(f"Could not remove stale {path}: {exc}")

def fix_permissions():
    if os.name != 'nt':
        try:
            uid = str(os.getuid())
            gid = str(os.getgid())
            subprocess.run(["chown", "-R", f"{uid}:{gid}", DATA_DIR],
                           stderr=subprocess.DEVNULL, timeout=10)
            Debugger.success("Permissions fixed.")
        except (subprocess.SubprocessError, OSError) as e:
            Debugger.warning(f"Permission fix skipped: {e}")

# ============== PHASE 1: SCANNING (ZAP ONLY) ==============
def run_scanning_phase():
    ensure_run_paths()
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
    # Target URL is directly accepted as authorized scope by the experienced VA operator
    Debugger.info(f"Target accepted: {url}")

    # ============== ENGAGEMENT TYPE SELECTION ==============
    print(f"\n{C.HEADER}{C.BOLD}[ ENGAGEMENT TYPE ]{C.END}")
    print(f"  {C.RED}1. 🏴‍☠️ BLACKBOX SCAN{C.END} — Unauthenticated, Production-Safe")
    print(f"  {C.GREEN}2. 🛡️  GREYBOX SCAN{C.END}  — Authenticated, Production-Safe")
    engagement_choice = input(f"{C.BOLD}👉 Choose Engagement Type (1-2, Default: 1): {C.END}").strip() or '1'

    scan_context = {'mode': 'BLACKBOX', 'cookie': None}
    if engagement_choice == '2':
        scan_context['mode'] = 'GREYBOX'
        print(f"\n{C.GREEN}🛡️  GREYBOX SCAN MODE ACTIVATED{C.END}")
        print(f"   {C.CYAN}ℹ️  Chế độ này dùng Session Cookie/Token chỉ cho kiểm chứng read-only trong phạm vi.{C.END}")
        print(f"   {C.CYAN}ℹ️  Không in/lưu raw cookie trên terminal hoặc báo cáo.{C.END}")
        auth_cookie = input(f"{C.BOLD}👉 Session Cookie (VD: PHPSESSID=abc123; token=xyz): {C.END}").strip()
        if auth_cookie:
            scan_context['cookie'] = auth_cookie
            os.environ['VA_AUTH_COOKIE'] = auth_cookie
            Debugger.success("Auth cookie/token received (redacted; not printed).")
        else:
            Debugger.warning("Không có Cookie. ZAP sẽ quét Unauthenticated nhưng pipeline vẫn chạy ở chế độ Production-Safe.")
    else:
        print(f"\n{C.RED}🏴‍☠️  BLACKBOX SCAN MODE — Unauthenticated, production-safe checks only.{C.END}")

    print(f"\n{C.CYAN}[ ZAP SCAN MODES ]{C.END}")
    print("1. ⚡ Quick Baseline Scan")
    print("2. 🐢 Full Deep Scan (lab/staging only)")
    print("3. 🕷️ AJAX Spider Scan")
    print("4. 🧯 Fragile Device Baseline (secondary source only)")
    
    choice = input(f"{C.BOLD}👉 Option (1-4): {C.END}").strip()
    script = "zap-baseline.py"; params = []
    if choice == '2':
        script = "zap-full-scan.py"
        Debugger.info("Full Deep Scan selected by operator. Running comprehensive scan...")
    elif choice == '3':
        params = ["-j"]
    elif choice == '4':
        params = ["-m", "1", "-T", "5", "-z", "-config spider.maxDepth=1 -config spider.threadCount=1 -config connection.timeoutInSecs=5"]
        Debugger.warning("Fragile Device Baseline selected: use ZAP as secondary scanner evidence only; do not treat it as definitive verification.")

    # Pre-flight check port HTTP/HTTPS cua target truoc khi chay Docker ZAP
    import socket
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    Debugger.info(f"Checking web service connectivity to {target_host}:{target_port}...")
    
    is_web_open = False
    try:
        with socket.create_connection((target_host, target_port), timeout=3):
            is_web_open = True
    except Exception:
        is_web_open = False

    if not is_web_open:
        Debugger.warning(f"Target {target_host}:{target_port} is NOT listening for Web connections (Connection Refused).")
        Debugger.info("Thiet bi này la thiet bi mang/ha tang (Non-Web Infrastructure Host) khong chay Web Server.")
        Debugger.info("ℹ️ ZAP web scan duoc bo qua vi target khong co web server.")
        Debugger.info("👉 Vui long chay OpenVAS network scan cho host nay, luu file XML vao raw/, sau do chon Option 2 (Process Only).")
        return None, scan_context

    # Xóa report cũ
    for old_report in [JSON_REPORT, HTML_REPORT]:
        try:
            if os.path.exists(old_report):
                os.remove(old_report)
        except OSError as e:
            Debugger.warning(f"Could not remove {old_report}: {e}")

    uid = str(os.getuid()) if os.name != 'nt' else '0'
    gid = str(os.getgid()) if os.name != 'nt' else '0'
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",
        "--memory", DOCKER_MEMORY_LIMIT,       # RAM limit
        "--memory-swap", DOCKER_MEMORY_LIMIT,   # Không swap
        "--shm-size", "2g",                    # Tăng shm_size chống crash trình duyệt (Firefox/Chrome) khi quét DOM XSS
        "-u", f"{uid}:{gid}",  # User hiện tại, KHÔNG dùng root (-u 0)
        "-v", f"{RAW_DIR}:/zap/wrk/:rw",
        "-t", ZAP_IMAGE, script,
        "-t", url, "-J", "zap_report.json", "-r", "zap_report.html",
    ]

    zap_auth_config_path = None

    # === GREYBOX: Inject Cookie vào ZAP qua Replacer config file tạm ===
    if scan_context['mode'] == 'GREYBOX' and scan_context.get('cookie'):
        cookie_val = scan_context['cookie']
        try:
            zap_auth_config_path = write_zap_auth_replacer_config(cookie_val, raw_dir=RAW_DIR)
            cmd.extend(["-z", f"-configfile {zap_container_config_path(zap_auth_config_path)}"])
            Debugger.success("ZAP Replacer auth header configured via temporary config file (redacted).")
        except ValueError as exc:
            Debugger.warning(f"ZAP authenticated scan disabled: {exc}")
    
    if params:
        cmd.extend(params)
    
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
    try:
        result = run_cmd(cmd, ignore_error=True, timeout=MAX_ZAP_SCAN_SECONDS)
    finally:
        remove_sensitive_temp_file(zap_auth_config_path)
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
    ensure_run_paths()
    Debugger.step("PHASE 2: DATA PROCESSING")

    py = get_python_exec()
    s_parse_zap = os.path.join(SCRIPTS_DIR, "parse_zap.py")
    s_parse_openvas = os.path.join(SCRIPTS_DIR, "parse_openvas.py")
    s_merge = os.path.join(SCRIPTS_DIR, "merge_vulns.py")
    s_map = os.path.join(SCRIPTS_DIR, "apply_attack_mapping.py")
    s_risk = os.path.join(SCRIPTS_DIR, "calculate_risk_priority.py")
    zap_findings_file = str(rt.normalized_dir() / "zap_findings.csv")
    zap_instances_file = str(rt.normalized_dir() / "zap_instances.csv")
    openvas_findings_file = str(rt.normalized_dir() / "openvas_findings.csv")
    openvas_report = find_latest_openvas_xml(RAW_DIR)

    has_zap = bool(JSON_REPORT and os.path.exists(JSON_REPORT))
    if not has_zap and not openvas_report:
        Debugger.error("Missing scanner input. Need ZAP JSON or OpenVAS XML under raw directory.")
        return

    if has_zap:
        run_cmd([py, s_parse_zap])
    else:
        Debugger.warning("No ZAP JSON found in raw directory — skipping ZAP parsing.")
        remove_stale_file(zap_findings_file, "current run has no ZAP JSON")
        remove_stale_file(zap_instances_file, "current run has no ZAP JSON")

    if openvas_report:
        Debugger.success(f"Found OpenVAS report: {os.path.basename(openvas_report)}")
        run_cmd([py, s_parse_openvas, openvas_report, openvas_findings_file])
    else:
        Debugger.warning("No OpenVAS XML found in data/raw/ — skipping OpenVAS parsing.")
        remove_stale_file(openvas_findings_file, "current run has no OpenVAS XML")
    
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
    ensure_run_paths()
    if scan_context is None:
        scan_context = {'mode': 'BLACKBOX', 'cookie': None}
    Debugger.step("PHASE 3: THREAT INTELLIGENCE ENRICHMENT")
    
    # Data paths
    enriched_file = str(rt.output_dir() / "vuln_attack_enriched.csv")
    queue_file = str(rt.output_dir() / "vuln_validation_queue.csv")
    
    # Load the enriched data
    if not os.path.exists(enriched_file):
        Debugger.error(f"Missing enriched file: {enriched_file}")
        return
    
    try:
        df = normalize_dataframe_schema(pd.read_csv(enriched_file))
        Debugger.success(f"Loaded {len(df)} vulnerabilities")
    except Exception as e:
        Debugger.error(f"Failed to load data: {e}")
        return
    
    # --- STEP 1: EPSS Enrichment ---
    Debugger.info("📡 Fetching EPSS scores for parsed CVEs...")
    all_cves = []
    for _, row in df.iterrows():
        all_cves.extend(extract_cves(row.get('cve'), row.get('cve_list')))

    if all_cves:
        Debugger.info(f"Found {len(all_cves)} CVE references ({len(set(all_cves))} unique) to query EPSS")
        df = enrich_dataframe_with_epss(df, cve_column='cve')
        nonzero_epss = len(df[df['epss_score'].fillna(0) > 0])
        Debugger.success(f"EPSS enrichment complete. {nonzero_epss} findings with non-zero EPSS.")
    else:
        Debugger.warning("No CVE IDs found. Skipping EPSS enrichment.")
        df['epss_score'] = 0.0
        df['epss_percentile'] = 0.0
        df['epss_source_cve'] = ''
        df['epss_all_json'] = '[]'
    
    # Initialize columns
    defaults = {
        'agent_status': '',
        'agent_command': '',
        'agent_evidence': '',
        'exploit_status': '',
        'exploit_evidence': '',
        'exploit_sources_json': '[]',
        'exploit_source_cves': '',
        'exploit_match_basis': '',
        'exploit_match_note': '',
        'exploit_context_review_required': False,
        'exploit_context_summary': '',
        'exploit_available': False,
        'verification_status': 'NOT_VERIFIED',
        'verification_evidence': '',
        'verification_method': '',
        'verification_command': '',
        'verification_error': '',
        'verification_confidence': '',
        'verification_started_at': '',
        'verification_completed_at': '',
        'verification_safe_mode': True,
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default
    text_columns = [
        'agent_status', 'agent_command', 'agent_evidence', 'exploit_status', 'exploit_evidence',
        'exploit_sources_json', 'exploit_source_cves', 'exploit_match_basis',
        'exploit_match_note', 'exploit_context_summary', 'verification_status',
        'verification_evidence', 'verification_method', 'verification_command',
        'verification_error', 'verification_confidence', 'verification_started_at',
        'verification_completed_at'
    ]
    for column in text_columns:
        df[column] = df[column].astype('object').where(pd.notna(df[column]), '')
        
    # --- STEP 1.5: Triage Gate (Noise Filtering) ---
    Debugger.info("🔍 Applying Context-Aware Triage Gate...")
    ignored_count = 0
    for idx, row in df.iterrows():
        severity = str(row.get("severity", "")).strip().upper()
        finding_name = str(row.get("finding_name", "")).strip().lower()
        cwes = (str(row.get("cwe", "")) + " " + str(row.get("cwe_list", ""))).lower()
        
        if severity in ["LOW", "INFORMATIONAL", "INFO"]:
            sensitive_keywords = ["password", "token", "credential", "private key", "backup", "leak", "disclosure", "cve-"]
            is_sensitive = "cwe-200" in cwes or any(k in finding_name for k in sensitive_keywords)
            
            if not is_sensitive:
                df.at[idx, "verification_status"] = "IGNORED_LOW_RISK"
                ignored_count += 1
                
    Debugger.success(f"Triage Gate completed. Ignored {ignored_count} low-risk noise findings.")
    
    # --- STEP 2: Exploit Intelligence & Threat Matching ---
    Debugger.step("⚡ RUNNING EXPLOIT-INTEL THREAT CHECK")
    print(f"{C.GREEN}⚡ Running CVE exploit-intel check (Exploit-DB, Metasploit, Nuclei)...{C.END}")
    
    for idx, row in df.iterrows():
        cves = extract_cves(row.get('cve'), row.get('cve_list'))
        
        if not cves:
            df.at[idx, 'exploit_status'] = 'NO_CVE_ID'
            df.at[idx, 'exploit_evidence'] = 'No CVE ID available for exploit intelligence check'
            df.at[idx, 'exploit_sources_json'] = '[]'
            df.at[idx, 'exploit_source_cves'] = ''
            df.at[idx, 'exploit_match_basis'] = 'NO_CVE'
            df.at[idx, 'exploit_match_note'] = 'No CVE ID was available for exploit-intelligence lookup.'
            df.at[idx, 'exploit_context_review_required'] = False
            df.at[idx, 'exploit_context_summary'] = 'No CVE ID was available for exploit-intelligence lookup.'
            df.at[idx, 'exploit_available'] = False
            # Legacy aliases for older CSV consumers.
            df.at[idx, 'agent_status'] = 'NO_CVE_ID'
            df.at[idx, 'agent_evidence'] = 'No CVE ID available for exploit intelligence check'
        else:
            cve_input = ','.join(cves)
            context_text = ' '.join(
                str(row.get(column, ''))
                for column in [
                    'finding_name',
                    'description',
                    'scanner_evidence',
                    'location',
                    'raw_reference',
                ]
            )
            detail = check_exploit_maturity_detail(cve_input, context_text=context_text)
            
            df.at[idx, 'exploit_status'] = detail['status']
            df.at[idx, 'exploit_evidence'] = detail['evidence']
            df.at[idx, 'exploit_sources_json'] = json.dumps(detail['sources'], ensure_ascii=False)
            df.at[idx, 'exploit_source_cves'] = ','.join(detail['matched_cves'])
            df.at[idx, 'exploit_match_basis'] = detail.get('match_basis', '')
            df.at[idx, 'exploit_match_note'] = detail.get('match_note', '')
            df.at[idx, 'exploit_context_review_required'] = detail.get('context_review_required', False)
            df.at[idx, 'exploit_context_summary'] = detail.get('context_summary', '')
            df.at[idx, 'exploit_available'] = detail['exploit_available']
            df.at[idx, 'agent_status'] = detail['status']
            df.at[idx, 'agent_evidence'] = detail['evidence']
            if detail['exploit_available']:
                print(f"   ⚠️  {cve_input}: {detail['status']} ({detail['evidence']})")
    
    public_count = len(df[df['exploit_available'] == True])
    Debugger.success(f"Exploit-intel check complete. Found {public_count} findings with public exploit/module/template evidence.")
    
    # --- STEP 3: Calculate Final Risk Score ---
    Debugger.step("CALCULATING FINAL RISK SCORES")
    
    severity_col = 'severity' if 'severity' in df.columns else 'risk' if 'risk' in df.columns else None
    
    risk_details = []
    
    for idx, row in df.iterrows():
        risk_details.append(calculate_risk_for_row(row))
    
    df['risk_score'] = [item['risk_score'] for item in risk_details]
    df['priority'] = [item['priority'] for item in risk_details]
    df['risk_reason'] = [item['risk_reason'] for item in risk_details]
    df['risk_components_json'] = [item['risk_components_json'] for item in risk_details]
    df = normalize_dataframe_schema(df)
    
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
    
    # --- XUẤT BÁO CÁO HTML DVAS (nếu có OpenVAS XML) ---
    s_html = os.path.join(SCRIPTS_DIR, "generate_html_report.py")
    openvas_report = find_latest_openvas_xml(RAW_DIR)
    html_generated = False
    if os.path.exists(s_html) and openvas_report:
        html_out_internal = str(rt.reports_dir() / "internal" / "dvas_security_report.html")
        html_out_customer = str(rt.reports_dir() / "customer_safe" / "dvas_security_report.html")
        run_cmd([py, s_html, openvas_report, "-o", html_out_internal], ignore_error=True)
        if os.path.exists(html_out_internal):
            shutil.copy2(html_out_internal, html_out_customer)
            html_generated = True

    # Final summary
    print(f"\n{'='*60}")
    print(f"{C.GREEN}{C.BOLD}✅ PIPELINE COMPLETE{C.END}")
    print(f"{'='*60}")
    print(f"📁 CSV: {queue_file}")
    print(f"📊 Internal Excel: {rt.reports_dir() / 'internal' / 'vuln_attack_report.xlsx'}")
    print(f"📊 Customer Excel: {rt.reports_dir() / 'customer_safe' / 'vuln_attack_report.xlsx'}")
    print(f"🧾 Internal JSON: {rt.reports_dir() / 'internal' / 'vuln_report_soc.json'}")
    print(f"🧾 Customer JSON: {rt.reports_dir() / 'customer_safe' / 'vuln_report_soc.json'}")
    if html_generated:
        print(f"🌐 Internal HTML: {rt.reports_dir() / 'internal' / 'dvas_security_report.html'}")
        print(f"🌐 Customer HTML: {rt.reports_dir() / 'customer_safe' / 'dvas_security_report.html'}")
    print(f"🔥 P1 (Critical): {len(df[df['priority'] == 'P1'])} items")
    print(f"⚠️  Public exploit/template available: {len(df[df['exploit_available'] == True])} items")

def main():
    _init_run_paths()  # Khởi tạo đường dẫn run với timestamp ĐÚNG thời điểm chạy
    os.system('cls' if os.name == 'nt' else 'clear')
    check_directories()
    
    # Kiểm tra Tool ngay từ đầu
    missing_tools = check_external_tools()

    print(f"{C.HEADER}{C.BOLD}🛡️   SECURITY PIPELINE (THREAT INTELLIGENCE)   🛡️{C.END}")
    Debugger.info(f"Active Run Directory: {rt.run_dir()}")
    
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
                print(f"  {C.RED}1. 🏴‍☠️ BLACKBOX{C.END} — Unauthenticated, Production-Safe")
                print(f"  {C.GREEN}2. 🛡️  GREYBOX{C.END}  — Authenticated, Production-Safe")
                eg = input(f"{C.BOLD}👉 Choose (1-2, Default: 1): {C.END}").strip() or '1'
                scan_context = {'mode': 'BLACKBOX', 'cookie': None}
                if eg == '2':
                    scan_context['mode'] = 'GREYBOX'
                    print(f"   {C.CYAN}ℹ️  Cookie/token chỉ dùng qua biến môi trường runtime VA_AUTH_COOKIE và không được in ra prompt/report.{C.END}")
                    cookie = input(f"{C.BOLD}👉 Session Cookie (VD: PHPSESSID=abc123): {C.END}").strip()
                    if cookie:
                        scan_context['cookie'] = cookie
                        os.environ['VA_AUTH_COOKIE'] = cookie
                        Debugger.success("Auth cookie/token received (redacted; not printed).")
                run_processing_phase()
                run_threat_intel_phase(u, missing_tools, scan_context)
                break
            elif c == '3': sys.exit(0)
    except KeyboardInterrupt: sys.exit(0)

if __name__ == "__main__":
    main()
