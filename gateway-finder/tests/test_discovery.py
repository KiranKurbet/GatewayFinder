"""
Unit tests for GatewayFinder core modules.
Run with: pytest tests/ -v
No network access or root required for these tests.
"""

import pytest
from unittest.mock import patch, MagicMock

from gateway_finder.utils.helpers import (
    is_valid_ip, is_valid_cidr, is_valid_mac,
    normalize_mac, read_mac_file,
)
from gateway_finder.core.discovery import GatewayInfo, DiscoveryEngine
from gateway_finder.core.fingerprint import FingerprintEngine, _OUI
from gateway_finder.core.scoring import ScoringEngine


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestValidation:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("10.0.0.1")
        assert is_valid_ip("8.8.8.8")

    def test_invalid_ip(self):
        assert not is_valid_ip("999.0.0.1")
        assert not is_valid_ip("not_an_ip")
        assert not is_valid_ip("")

    def test_valid_cidr(self):
        assert is_valid_cidr("192.168.1.0/24")
        assert is_valid_cidr("10.0.0.0/8")

    def test_invalid_cidr(self):
        assert not is_valid_cidr("192.168.1.0/33")
        assert not is_valid_cidr("not/cidr")

    def test_valid_mac(self):
        assert is_valid_mac("00:11:22:33:44:55")
        assert is_valid_mac("00-11-22-33-44-55")
        assert is_valid_mac("AA:BB:CC:DD:EE:FF")

    def test_invalid_mac(self):
        assert not is_valid_mac("00:11:22:33:44")
        assert not is_valid_mac("ZZ:11:22:33:44:55")
        assert not is_valid_mac("")

    def test_normalize_mac_colon(self):
        assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"

    def test_normalize_mac_dash(self):
        assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"

    def test_normalize_mac_lowercase(self):
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_empty(self):
        assert normalize_mac("") == ""

    def test_normalize_mac_invalid(self):
        assert normalize_mac("00:11:ZZ:33:44:55") == ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAC file parsing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestMacFileParsing:
    def test_plain_mac(self, tmp_path):
        f = tmp_path / "macs.txt"
        f.write_text("00:11:22:33:44:55\n")
        entries = read_mac_file(str(f))
        assert len(entries) == 1
        assert entries[0]["mac"] == "00:11:22:33:44:55"
        assert entries[0]["ip"] == ""

    def test_ip_and_mac(self, tmp_path):
        f = tmp_path / "macs.txt"
        f.write_text("192.168.1.1 00:11:22:33:44:55\n")
        entries = read_mac_file(str(f))
        assert entries[0]["ip"]  == "192.168.1.1"
        assert entries[0]["mac"] == "00:11:22:33:44:55"

    def test_mac_then_ip(self, tmp_path):
        f = tmp_path / "macs.txt"
        f.write_text("00:11:22:33:44:55 10.0.0.1\n")
        entries = read_mac_file(str(f))
        assert entries[0]["ip"] == "10.0.0.1"

    def test_comment_skipped(self, tmp_path):
        f = tmp_path / "macs.txt"
        f.write_text("# comment\n00:11:22:33:44:55\n")
        entries = read_mac_file(str(f))
        assert len(entries) == 1

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert read_mac_file(str(f)) == []

    def test_missing_file(self):
        assert read_mac_file("/nonexistent/path/macs.txt") == []

    def test_dash_format_mac(self, tmp_path):
        f = tmp_path / "macs.txt"
        f.write_text("00-11-22-33-44-55\n")
        entries = read_mac_file(str(f))
        assert entries[0]["mac"] == "00:11:22:33:44:55"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GatewayInfo dataclass
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestGatewayInfo:
    def test_default_fields(self):
        gw = GatewayInfo()
        assert gw.ip              == ""
        assert gw.security_score  == -1
        assert gw.vulnerabilities == []
        assert gw.open_ports      == []

    def test_to_dict_completeness(self):
        gw   = GatewayInfo(ip="192.168.1.1", vendor="Cisco")
        data = gw.to_dict()
        assert data["ip"]     == "192.168.1.1"
        assert data["vendor"] == "Cisco"
        for key in ("mac", "hostname", "open_ports", "security_score",
                    "risk_level", "recommendations"):
            assert key in data

    def test_to_dict_open_ports_serialisable(self):
        gw = GatewayInfo(ip="10.0.0.1")
        gw.open_ports = [22, 80, 443]
        d = gw.to_dict()
        assert isinstance(d["open_ports"], list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Fingerprint Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestFingerprintEngine:
    def setup_method(self):
        self.fp = FingerprintEngine(timeout=1)

    def test_oui_cisco(self):
        vendor = self.fp._vendor_from_mac("00:00:0C:AA:BB:CC")
        assert vendor == "Cisco"

    def test_oui_mikrotik(self):
        vendor = self.fp._vendor_from_mac("00:0C:42:AA:BB:CC")
        assert vendor == "MikroTik"

    def test_oui_unknown(self):
        vendor = self.fp._vendor_from_mac("FE:DC:BA:98:76:54")
        assert vendor == ""

    def test_virtual_hsrp_mac(self):
        vendor = self.fp._vendor_from_mac("00:00:0C:07:AC:01")
        assert "HSRP" in vendor

    def test_virtual_vrrp_mac(self):
        vendor = self.fp._vendor_from_mac("00:00:5E:00:01:01")
        assert "VRRP" in vendor

    def test_ttl_windows(self):
        assert "Windows" in FingerprintEngine._map_ttl(128)
        assert "Windows" in FingerprintEngine._map_ttl(125)

    def test_ttl_linux(self):
        assert "Linux" in FingerprintEngine._map_ttl(64)
        assert "Linux" in FingerprintEngine._map_ttl(62)

    def test_ttl_cisco(self):
        result = FingerprintEngine._map_ttl(255)
        assert "Cisco" in result or "Network" in result

    def test_ttl_unknown(self):
        result = FingerprintEngine._map_ttl(42)
        assert "42" in result

    def test_oui_table_no_empty_keys(self):
        for key in _OUI:
            assert len(key) > 0
            assert key == key.upper()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scoring Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestScoringEngine:
    def setup_method(self):
        self.scorer = ScoringEngine()

    def _gw(self, **kw) -> GatewayInfo:
        gw = GatewayInfo(ip="192.168.1.1")
        for k, v in kw.items():
            setattr(gw, k, v)
        return gw

    # Security score
    def test_clean_gw_scores_100(self):
        gw = self._gw()
        self.scorer.run(gw)
        assert gw.security_score == 100

    def test_telnet_deducts_30(self):
        gw = self._gw(has_telnet=True)
        self.scorer.run(gw)
        assert gw.security_score == 70

    def test_snmp_default_community_deducts(self):
        gw = self._gw(has_snmp=True, snmp_community="public")
        self.scorer.run(gw)
        assert gw.security_score <= 75

    def test_weak_tls_deducts_15(self):
        gw = self._gw(weak_tls=True)
        self.scorer.run(gw)
        assert gw.security_score == 85

    def test_multiple_issues_stack(self):
        gw = self._gw(has_telnet=True, weak_tls=True, self_signed_cert=True)
        self.scorer.run(gw)
        assert gw.security_score <= 45

    def test_score_never_below_zero(self):
        gw = self._gw(
            has_telnet=True, has_snmp=True, snmp_community="public",
            weak_tls=True, self_signed_cert=True,
            open_ports=list(range(20)),   # many ports
        )
        self.scorer.run(gw)
        assert gw.security_score >= 0

    # Risk level
    def test_risk_low(self):
        gw = self._gw()
        self.scorer.run(gw)
        assert gw.risk_level == "LOW"

    def test_risk_critical(self):
        gw = self._gw(
            has_telnet=True, has_snmp=True, snmp_community="public",
            weak_tls=True, self_signed_cert=True,
            open_ports=[23, 161, 8291, 8728, 623, 80, 22, 179],
        )
        self.scorer.run(gw)
        assert gw.risk_level in ("CRITICAL", "HIGH")

    # Exposure score
    def test_no_ports_zero_exposure(self):
        gw = self._gw()
        self.scorer.run(gw)
        assert gw.exposure_score == 0

    def test_telnet_port_high_exposure(self):
        gw = self._gw(open_ports=[23])
        self.scorer.run(gw)
        assert gw.exposure_score >= 40

    # Availability
    def test_no_routing_zero_availability(self):
        gw = self._gw()
        self.scorer.run(gw)
        assert gw.availability_score == 0

    def test_icmp_routing_adds_50(self):
        gw = self._gw(routes_icmp=True)
        self.scorer.run(gw)
        assert gw.availability_score >= 50

    # Recommendations
    def test_telnet_gets_recommendation(self):
        gw = self._gw(has_telnet=True)
        self.scorer.run(gw)
        assert any("Telnet" in r for r in gw.recommendations)

    def test_clean_gw_no_critical_recs(self):
        gw = self._gw(routes_icmp=True)
        self.scorer.run(gw)
        # no critical vulnerability recommendations
        assert not any("CRITICAL" in r for r in gw.recommendations)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Reporter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestReporter:
    def _sample_gateways(self):
        gw = GatewayInfo(
            ip="192.168.1.1", mac="00:11:22:33:44:55",
            vendor="Cisco", os_guess="Cisco IOS",
            is_default=True, routes_icmp=True,
            open_ports=[22, 80], has_telnet=False,
            security_score=90, exposure_score=15,
            availability_score=60, risk_level="LOW",
            vulnerabilities=[],
            recommendations=["Enable HTTPS management"],
        )
        return [gw]

    def test_json_export(self, tmp_path):
        from gateway_finder.reports.reporter import Reporter
        import json
        rpt  = Reporter(self._sample_gateways())
        path = str(tmp_path / "out.json")
        rpt.save_json(path)
        data = json.loads(open(path).read())
        assert "gateways" in data
        assert data["gateways"][0]["ip"] == "192.168.1.1"

    def test_csv_export(self, tmp_path):
        from gateway_finder.reports.reporter import Reporter
        import csv as _csv
        rpt  = Reporter(self._sample_gateways())
        path = str(tmp_path / "out.csv")
        rpt.save_csv(path)
        rows = list(_csv.DictReader(open(path)))
        assert len(rows) == 1
        assert rows[0]["ip"] == "192.168.1.1"

    def test_html_export(self, tmp_path):
        from gateway_finder.reports.reporter import Reporter
        rpt  = Reporter(self._sample_gateways())
        path = str(tmp_path / "out.html")
        rpt.save_html(path)
        html = open(path).read()
        assert "192.168.1.1" in html
        assert "GatewayFinder" in html
        assert "<!DOCTYPE html>" in html

    def test_summary_keys(self):
        from gateway_finder.reports.reporter import Reporter
        rpt = Reporter(self._sample_gateways())
        s   = rpt._summary()
        for key in ("total_gateways", "routing_confirmed",
                    "with_vulnerabilities", "critical_risk", "high_risk"):
            assert key in s
