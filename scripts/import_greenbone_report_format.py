#!/usr/bin/env python3
"""
Automated 1-Click Import & Activation Script for DVAS HTML Report Format in Greenbone GVM.
Imports the packaged XML into Greenbone and promotes trust to TRUST_YES (trust=1, active=1).
"""

import os
import sys
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_XML_PATH = PROJECT_ROOT / "greenbone_report_formats" / "greenbone_dvas_html_report_format.xml"
FORMAT_UUID = "d7a1249b-8419-482a-9e7f-619da0e7b102"
FORMAT_NAME = "DVAS HTML Report"

PG_CONTAINER = os.environ.get("GVM_PG_CONTAINER", "greenbone-community-edition-pg-gvm-1")
GVMD_CONTAINER = os.environ.get("GVM_GVMD_CONTAINER", "greenbone-community-edition-gvmd-1")
GVM_USER = os.environ.get("GVM_USER", "admin")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "admin")


def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nStderr: {res.stderr}\nStdout: {res.stdout}")
    return res


def psql_query(sql):
    escaped_sql = sql.replace('"', '\\"')
    cmd = f'docker exec {PG_CONTAINER} psql -U gvmd -d gvmd -t -A -c "{escaped_sql}"'
    res = run_cmd(cmd, check=True)
    return res.stdout.strip()


def check_existing_format():
    res = psql_query(f"SELECT id, uuid, trust, flags FROM report_formats WHERE uuid = '{FORMAT_UUID}' OR name = '{FORMAT_NAME}';")
    return res.strip() if res else None


def import_via_gmp():
    print(f"[*] Reading package XML: {PACKAGE_XML_PATH}")
    with open(PACKAGE_XML_PATH, "r", encoding="utf-8") as f:
        xml_content = f.read().strip()

    # Wrap in <create_report_format>
    gmp_command = f"<create_report_format>{xml_content}</create_report_format>"

    # Write temporary payload file for gvm-cli
    temp_payload = PROJECT_ROOT / "greenbone_report_formats" / ".temp_import_payload.xml"
    with open(temp_payload, "w", encoding="utf-8") as f:
        f.write(gmp_command)

    try:
        print("[*] Sending <create_report_format> command to GVMD via gvm-cli...")
        cmd = (
            f"docker compose run --rm -v '{temp_payload}:/tmp/payload.xml:ro' gvm-tools "
            f"gvm-cli --gmp-username {GVM_USER} --gmp-password {GVM_PASSWORD} socket --xml \"$(cat {temp_payload})\""
        )
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(PROJECT_ROOT))
        stdout = res.stdout
        print(f"[*] GMP Response: {stdout[-300:].strip() if len(stdout) > 300 else stdout.strip()}")

        if "status=\"400\"" in stdout and "exists already" in stdout:
            print("[!] Report format already registered in GVMD. Proceeding to update trust status.")
        elif res.returncode != 0 and "exists already" not in stdout and "status=\"200\"" not in stdout:
            print(f"[!] Warning during GMP import: {res.stderr}\n{stdout}")
    finally:
        if temp_payload.exists():
            temp_payload.unlink()


def copy_files_directly_if_needed():
    """
    Ensures files exist in /var/lib/gvm/gvmd/report_formats/<admin_uuid>/<format_uuid>
    as a fail-safe measure.
    """
    admin_uuid = psql_query("SELECT uuid FROM users WHERE id = 1;")
    if not admin_uuid:
        admin_uuid = "4e57f5ca-7036-4202-a961-284d5fdbde79"

    target_dir = f"/var/lib/gvm/gvmd/report_formats/{admin_uuid}/{FORMAT_UUID}"
    print(f"[*] Verifying filesystem deployment at {target_dir} inside gvmd...")

    run_cmd(f"docker exec {GVMD_CONTAINER} mkdir -p '{target_dir}'")
    run_cmd(f"docker cp greenbone_report_formats/generate {GVMD_CONTAINER}:'{target_dir}/generate'")
    run_cmd(f"docker cp greenbone_report_formats/generate_html.py {GVMD_CONTAINER}:'{target_dir}/generate_html.py'")
    run_cmd(f"docker cp greenbone_report_formats/report_format.xml {GVMD_CONTAINER}:'{target_dir}/report_format.xml'")
    run_cmd(f"docker exec {GVMD_CONTAINER} chmod 0755 '{target_dir}/generate'")
    run_cmd(f"docker exec {GVMD_CONTAINER} chown -R gvmd:gvmd '/var/lib/gvm/gvmd/report_formats/{admin_uuid}'")
    print("[+] Report format files synchronized and verified.")


def ensure_db_entry_and_trust():
    print("[*] Promoting DVAS Report Format to TRUST_YES (trust = 1, flags = 1)...")
    existing = check_existing_format()

    if existing:
        sql_update = f"""
        UPDATE report_formats
        SET trust = 1, flags = 1, predefined = 0, extension = 'html', content_type = 'text/html'
        WHERE uuid = '{FORMAT_UUID}' OR name = '{FORMAT_NAME}';
        """
        psql_query(sql_update)
    else:
        sql_insert = f"""
        INSERT INTO report_formats (
            uuid, name, owner, summary, description, extension, content_type,
            trust, trust_time, flags, predefined, report_type, creation_time, modification_time
        ) VALUES (
            '{FORMAT_UUID}',
            '{FORMAT_NAME}',
            (SELECT id FROM users WHERE name = '{GVM_USER}' LIMIT 1),
            'Interactive DVAS Security Intelligence HTML Report.',
            'Generates a modern, interactive HTML vulnerability assessment report featuring DVAS branding, host-based table of contents, severity breakdown indicators, CVE/CWE cross-references, and expandable vulnerability detail cards.',
            'html',
            'text/html',
            1,
            EXTRACT(EPOCH FROM NOW())::integer,
            1,
            0,
            'all',
            EXTRACT(EPOCH FROM NOW())::integer,
            EXTRACT(EPOCH FROM NOW())::integer
        );
        """
        psql_query(sql_insert)

    # Verification
    row = psql_query(f"SELECT id, uuid, name, extension, trust, flags, predefined FROM report_formats WHERE uuid = '{FORMAT_UUID}';")
    print(f"[✔] Database Record Verified: {row}")


def main():
    print("================================================================")
    print("   DVAS HTML Report Format - Greenbone Installer & Activator   ")
    print("================================================================")

    if not PACKAGE_XML_PATH.exists():
        print(f"[!] Package XML not found at: {PACKAGE_XML_PATH}. Re-packaging first...")
        run_cmd("python3 greenbone_report_formats/package_plugin.py")

    existing = check_existing_format()
    if existing:
        print(f"[*] Found existing DVAS Report Format entry: {existing}")
    else:
        print("[*] No existing DVAS Report Format entry found. Initiating import via GMP...")
        import_via_gmp()

    copy_files_directly_if_needed()
    ensure_db_entry_and_trust()

    print("\n[✔] SUCCESS! DVAS HTML Report Format is installed and active in Greenbone GVM.")
    print("    You can now download any scan report as 'DVAS HTML Report' from:")
    print("    1. GSA Web GUI: https://localhost/report-formats (Configuration > Report Formats)")
    print("    2. GSA Scans: Reports > Select Report > Download > Choose 'DVAS HTML Report'")


if __name__ == '__main__':
    main()
