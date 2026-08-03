#!/usr/bin/env python3
"""Regression checks for the bundled Greenbone/OpenVAS VA configs."""

from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPENVAS_DIR = ROOT / "OpenVas-config"

CONFIGS = {
    "applications": {
        "config": "va-applications.xml",
        "config_uuid": "465c8cc8-9e48-506f-855a-2de3a658b659",
        "port_list": "portlist-applications.xml",
        "port_uuid": "eb96b684-315b-5a54-afe9-4f580955ca96",
        "families": 19,
        "nvt_count": 25600,
        "max_nvt_count": 25609,
        "services_parallelism": "4",
        "nmap_timing": "Normal",
        "ping_timing": "Normal",
        "time_between_request": "50",
        "timeout_retry": "2",
        "open_sock_max_attempts": "3",
        "checks_read_timeout": "8",
        "required_families": {
            "Databases",
            "Product detection",
            "Service detection",
            "SSL and TLS",
            "Web application abuses",
            "Web Servers",
        },
        "excluded_oids": {
            "1.3.6.1.4.1.25623.1.0.810002",
            "1.3.6.1.4.1.25623.1.0.810003",
            "1.3.6.1.4.1.25623.1.0.103533",
            "1.3.6.1.4.1.25623.1.0.106326",
            "1.3.6.1.4.1.25623.1.0.113013",
            "1.3.6.1.4.1.25623.1.0.114987",
            "1.3.6.1.4.1.25623.1.0.802476",
            "1.3.6.1.4.1.25623.1.0.802495",
            "1.3.6.1.4.1.25623.1.0.813883",
            "1.3.6.1.4.1.25623.1.0.902928",
        },
    },
    "network_devices": {
        "config": "va-network-devices.xml",
        "config_uuid": "373718eb-a31c-505b-8e56-2c186f132cce",
        "port_list": "portlist-network-devices.xml",
        "port_uuid": "db16db9e-7361-50cf-9813-5df5f631dabe",
        "families": 21,
        "nvt_count": 25023,
        "max_nvt_count": 25032,
        "services_parallelism": "2",
        "nmap_timing": "Polite",
        "ping_timing": "Polite",
        "time_between_request": "200",
        "timeout_retry": "1",
        "open_sock_max_attempts": "2",
        "checks_read_timeout": "10",
        "required_families": {
            "CISCO",
            "Huawei",
            "JunOS Local Security Checks",
            "Product detection",
            "SNMP",
            "SSL and TLS",
            "Web Servers",
        },
        "excluded_oids": {
            "1.3.6.1.4.1.25623.1.0.810002",
            "1.3.6.1.4.1.25623.1.0.810003",
            "1.3.6.1.4.1.25623.1.0.104329",
            "1.3.6.1.4.1.25623.1.0.105434",
            "1.3.6.1.4.1.25623.1.0.105435",
            "1.3.6.1.4.1.25623.1.0.105442",
            "1.3.6.1.4.1.25623.1.0.105443",
            "1.3.6.1.4.1.25623.1.0.140114",
            "1.3.6.1.4.1.25623.1.0.23938",
            "1.3.6.1.4.1.25623.1.0.106326",
            "1.3.6.1.4.1.25623.1.0.113013",
            "1.3.6.1.4.1.25623.1.0.114987",
            "1.3.6.1.4.1.25623.1.0.802476",
            "1.3.6.1.4.1.25623.1.0.802495",
            "1.3.6.1.4.1.25623.1.0.813883",
            "1.3.6.1.4.1.25623.1.0.902928",
        },
    },
    "security_devices": {
        "config": "va-security-devices.xml",
        "config_uuid": "603fd718-e69e-5501-a803-787ce81b7776",
        "port_list": "portlist-security-devices.xml",
        "port_uuid": "a0ff929f-d4d0-55d3-986c-8493dd1c1bc0",
        "families": 26,
        "nvt_count": 26498,
        "max_nvt_count": 26507,
        "services_parallelism": "2",
        "nmap_timing": "Polite",
        "ping_timing": "Polite",
        "time_between_request": "200",
        "timeout_retry": "1",
        "open_sock_max_attempts": "2",
        "checks_read_timeout": "10",
        "required_families": {
            "CISCO",
            "F5 Local Security Checks",
            "FortiOS Local Security Checks",
            "Palo Alto PAN-OS Local Security Checks",
            "Policy",
            "Product detection",
            "SNMP",
            "SSL and TLS",
            "Web Servers",
        },
        "excluded_oids": {
            "1.3.6.1.4.1.25623.1.0.810002",
            "1.3.6.1.4.1.25623.1.0.810003",
            "1.3.6.1.4.1.25623.1.0.104329",
            "1.3.6.1.4.1.25623.1.0.105434",
            "1.3.6.1.4.1.25623.1.0.105435",
            "1.3.6.1.4.1.25623.1.0.105442",
            "1.3.6.1.4.1.25623.1.0.105443",
            "1.3.6.1.4.1.25623.1.0.140114",
            "1.3.6.1.4.1.25623.1.0.23938",
            "1.3.6.1.4.1.25623.1.0.106326",
            "1.3.6.1.4.1.25623.1.0.113013",
            "1.3.6.1.4.1.25623.1.0.114987",
            "1.3.6.1.4.1.25623.1.0.802476",
            "1.3.6.1.4.1.25623.1.0.802495",
            "1.3.6.1.4.1.25623.1.0.813883",
            "1.3.6.1.4.1.25623.1.0.902928",
        },
    },
    "workstations_servers": {
        "config": "va-workstations-servers.xml",
        "config_uuid": "da2540b9-58ef-5efc-8de9-a9add993c88d",
        "port_list": "portlist-workstations-servers.xml",
        "port_uuid": "637588ff-9a60-5c1d-86e6-371433aac3dd",
        "families": 46,
        "nvt_count": 177116,
        "max_nvt_count": 177125,
        "services_parallelism": "4",
        "nmap_timing": "Normal",
        "ping_timing": "Normal",
        "time_between_request": "25",
        "timeout_retry": "2",
        "open_sock_max_attempts": "3",
        "checks_read_timeout": "8",
        "required_families": {
            "Debian Local Security Checks",
            "Fedora Local Security Checks",
            "Red Hat Local Security Checks",
            "Ubuntu Local Security Checks",
            "Windows : Microsoft Bulletins",
            "Product detection",
            "SSL and TLS",
            "Web Servers",
        },
        "excluded_oids": {
            "1.3.6.1.4.1.25623.1.0.810002",
            "1.3.6.1.4.1.25623.1.0.810003",
            "1.3.6.1.4.1.25623.1.0.103533",
            "1.3.6.1.4.1.25623.1.0.106326",
            "1.3.6.1.4.1.25623.1.0.113013",
            "1.3.6.1.4.1.25623.1.0.114987",
            "1.3.6.1.4.1.25623.1.0.802476",
            "1.3.6.1.4.1.25623.1.0.802495",
            "1.3.6.1.4.1.25623.1.0.813883",
            "1.3.6.1.4.1.25623.1.0.902928",
        },
    },
}

PORT_LISTS = {
    "applications": {
        "file": "portlist-applications.xml",
        "uuid": "eb96b684-315b-5a54-afe9-4f580955ca96",
        "tcp": 1068,
        "udp": 7,
    },
    "network_devices": {
        "file": "portlist-network-devices.xml",
        "uuid": "db16db9e-7361-50cf-9813-5df5f631dabe",
        "tcp": 1041,
        "udp": 16,
    },
    "security_devices": {
        "file": "portlist-security-devices.xml",
        "uuid": "a0ff929f-d4d0-55d3-986c-8493dd1c1bc0",
        "tcp": 1039,
        "udp": 15,
    },
    "workstations_servers": {
        "file": "portlist-workstations-servers.xml",
        "uuid": "637588ff-9a60-5c1d-86e6-371433aac3dd",
        "tcp": 1059,
        "udp": 15,
    },
    "full_tcp_udp_optional": {
        "file": "portlist-full-tcp-udp.xml",
        "uuid": "a40dbc6a-f819-5d71-bf6a-725dce3ee69b",
        "tcp": 65535,
        "udp": 65535,
    },
}

FORBIDDEN_BASELINE_FAMILIES = {
    "Brute force attacks",
    "Default Accounts",
    "Denial of Service",
}


def parse(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def pref_value(config: ET.Element, name: str, oid: str | None = None, pref_id: str | None = None) -> str:
    matches: list[str] = []
    for pref in config.find("preferences").findall("preference"):
        nvt = pref.find("nvt")
        pref_oid = nvt.get("oid") if nvt is not None else ""
        if oid is not None and pref_oid != oid:
            continue
        if pref_id is not None and pref.findtext("id") != pref_id:
            continue
        if pref.findtext("name") != name:
            continue
        matches.append(pref.findtext("value") or "")
    if len(matches) != 1:
        raise AssertionError(f"expected one preference {name!r}, found {len(matches)}")
    return matches[0]


def port_count(start: str, end: str) -> int:
    return int(end) - int(start) + 1


def render_range(port_range: ET.Element) -> str:
    start = port_range.findtext("start")
    end = port_range.findtext("end")
    prefix = "T" if port_range.findtext("type") == "TCP" else "U"
    return f"{prefix}:{start}" if start == end else f"{prefix}:{start}-{end}"


class OpenVASConfigTests(unittest.TestCase):
    def test_scan_configs_have_stable_identity_and_metadata(self):
        for role, expected in CONFIGS.items():
            with self.subTest(role=role):
                root = parse(OPENVAS_DIR / "scan-configs" / expected["config"])
                self.assertEqual(root.tag, "get_configs_response")
                self.assertEqual(root.get("status"), "200")
                config = root.find("config")
                self.assertEqual(config.get("id"), expected["config_uuid"])

                families = config.find("families").findall("family")
                family_names = [family.findtext("name") for family in families]
                self.assertEqual(len(families), expected["families"])
                self.assertEqual(int(config.findtext("family_count")), expected["families"])
                self.assertEqual(sum(int(family.findtext("nvt_count")) for family in families), expected["nvt_count"])
                self.assertEqual(sum(int(family.findtext("max_nvt_count")) for family in families), expected["max_nvt_count"])
                self.assertEqual(int(config.findtext("nvt_count")), expected["nvt_count"])
                self.assertEqual(int(config.findtext("known_nvt_count")), expected["nvt_count"])
                self.assertEqual(int(config.findtext("max_nvt_count")), expected["max_nvt_count"])
                self.assertTrue(expected["required_families"].issubset(set(family_names)))
                self.assertFalse(FORBIDDEN_BASELINE_FAMILIES.intersection(family_names))

    def test_scan_config_safety_preferences(self):
        for role, expected in CONFIGS.items():
            with self.subTest(role=role):
                config = parse(OPENVAS_DIR / "scan-configs" / expected["config"]).find("config")
                self.assertEqual(pref_value(config, "safe_checks"), "1")
                self.assertEqual(pref_value(config, "optimize_test"), "1")
                self.assertEqual(pref_value(config, "auto_enable_dependencies"), "1")
                self.assertEqual(
                    pref_value(config, "Disable brute force checks", "1.3.6.1.4.1.25623.1.0.103697", "3"),
                    "yes",
                )
                self.assertEqual(
                    pref_value(config, "Disable default account checks", "1.3.6.1.4.1.25623.1.0.103697", "4"),
                    "yes",
                )
                self.assertEqual(
                    pref_value(config, "Number of connections done in parallel :", "1.3.6.1.4.1.25623.1.0.10330", "2"),
                    expected["services_parallelism"],
                )
                self.assertEqual(
                    pref_value(config, "Timing policy :", "1.3.6.1.4.1.25623.1.0.14259", "7"),
                    expected["nmap_timing"],
                )
                self.assertEqual(
                    pref_value(config, "nmap timing policy", "1.3.6.1.4.1.25623.1.0.100315", "14"),
                    expected["ping_timing"],
                )
                self.assertEqual(pref_value(config, "time_between_request"), expected["time_between_request"])
                self.assertEqual(pref_value(config, "timeout_retry"), expected["timeout_retry"])
                self.assertEqual(pref_value(config, "open_sock_max_attempts"), expected["open_sock_max_attempts"])
                self.assertEqual(pref_value(config, "checks_read_timeout"), expected["checks_read_timeout"])

    def test_selectors_match_selected_families_and_port_scanners(self):
        for role, expected in CONFIGS.items():
            with self.subTest(role=role):
                config = parse(OPENVAS_DIR / "scan-configs" / expected["config"]).find("config")
                family_names = {family.findtext("name") for family in config.find("families").findall("family")}
                selectors = config.find("nvt_selectors").findall("nvt_selector")
                included_families = {
                    selector.findtext("family_or_nvt")
                    for selector in selectors
                    if selector.findtext("include") == "1" and selector.findtext("type") == "1"
                }
                included_oids = {
                    selector.findtext("family_or_nvt")
                    for selector in selectors
                    if selector.findtext("include") == "1" and selector.findtext("type") == "2"
                }
                excluded_oids = {
                    selector.findtext("family_or_nvt")
                    for selector in selectors
                    if selector.findtext("include") == "0" and selector.findtext("type") == "2"
                }
                self.assertEqual(included_families, family_names - {"Port scanners"})
                self.assertIn("1.3.6.1.4.1.25623.1.0.100315", included_oids)
                self.assertIn("1.3.6.1.4.1.25623.1.0.14259", included_oids)
                self.assertEqual(excluded_oids, expected["excluded_oids"])

    def test_workstations_lsc_file_search_is_constrained(self):
        config = parse(OPENVAS_DIR / "scan-configs" / CONFIGS["workstations_servers"]["config"]).find("config")
        oid = "1.3.6.1.4.1.25623.1.0.100509"
        self.assertEqual(
            pref_value(config, "Descend directories on other filesystem (don't add -xdev to find)", oid, "2"),
            "no",
        )
        self.assertEqual(pref_value(config, "Disable file search via WMI on Windows", oid, "5"), "yes")
        self.assertEqual(
            pref_value(config, "Integer that sets the directory depth when using 'find' on unixoide systems", oid, "7"),
            "8",
        )

    def test_no_embedded_password_or_file_values(self):
        for path in (OPENVAS_DIR / "scan-configs").glob("*.xml"):
            with self.subTest(path=path.name):
                config = parse(path).find("config")
                for pref in config.find("preferences").findall("preference"):
                    if pref.findtext("type") in {"password", "file"}:
                        self.assertIn(pref.findtext("value"), {None, ""})

    def test_port_lists_match_range_files_and_counts(self):
        for role, expected in PORT_LISTS.items():
            with self.subTest(role=role):
                xml_path = OPENVAS_DIR / "port-lists" / expected["file"]
                root = parse(xml_path)
                self.assertEqual(root.tag, "get_port_lists_response")
                self.assertEqual(root.get("status"), "200")
                port_list = root.find("port_list")
                self.assertEqual(port_list.get("id"), expected["uuid"])

                ranges = port_list.find("port_ranges").findall("port_range")
                rendered = ",".join(render_range(port_range) for port_range in ranges)
                range_file = xml_path.with_suffix(".range.txt")
                if range_file.exists():
                    self.assertEqual(rendered, range_file.read_text().strip())

                tcp = sum(port_count(r.findtext("start"), r.findtext("end")) for r in ranges if r.findtext("type") == "TCP")
                udp = sum(port_count(r.findtext("start"), r.findtext("end")) for r in ranges if r.findtext("type") == "UDP")
                self.assertEqual(int(port_list.findtext("port_count/tcp")), tcp)
                self.assertEqual(int(port_list.findtext("port_count/udp")), udp)
                self.assertEqual(int(port_list.findtext("port_count/all")), tcp + udp)
                self.assertEqual(tcp, expected["tcp"])
                self.assertEqual(udp, expected["udp"])


if __name__ == "__main__":
    unittest.main()
