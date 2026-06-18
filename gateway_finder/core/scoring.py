"""
Gateway Finder - Intelligence Scoring Engine
Computes Security Score, Exposure Score, Availability Score,
Risk Level, and actionable recommendations from scan data.
Designed to be extendable with an LLM backend later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from gateway_finder.core.discovery import GatewayInfo


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scoring constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Security score deductions  (penalty, label, applies-when)
_SEC_PENALTIES = [
    (30, "Telnet enabled",                  lambda g: g.has_telnet),
    (25, "SNMP default community string",   lambda g: g.has_snmp and g.snmp_community in ("public","private","")),
    (15, "Weak TLS (1.0/1.1)",             lambda g: g.weak_tls),
    (10, "Self-signed certificate",         lambda g: g.self_signed_cert),
    (10, "HTTP management (no HTTPS)",      lambda g: 80 in g.open_ports and 443 not in g.open_ports),
    (10, "MikroTik Winbox exposed",         lambda g: 8291 in g.open_ports),
    (10, "MikroTik API exposed",            lambda g: 8728 in g.open_ports),
    (10, "IPMI/BMC exposed",               lambda g: 623 in g.open_ports),
    (5,  "SNMP port reachable",            lambda g: g.has_snmp),
    (5,  "Excessive open ports (>6)",       lambda g: len(g.open_ports) > 6),
]

# Exposure score additions (each confirmed exposed service adds weight)
_EXPOSURE_WEIGHTS = {
    23:   40,   # Telnet
    161:  30,   # SNMP
    80:   15,   # HTTP management
    8291: 20,   # Winbox
    8728: 20,   # RouterOS API
    623:  25,   # IPMI
    179:  10,   # BGP
    22:   10,   # SSH (minor, expected)
    443:   5,   # HTTPS (expected, low weight)
    8080: 10,
    8443:  5,
}

# Recommendation templates keyed by condition
_RECOMMENDATIONS = [
    (lambda g: g.has_telnet,
     "CRITICAL: Disable Telnet (port 23) and use SSH for remote management."),
    (lambda g: g.has_snmp and g.snmp_community in ("public", "private"),
     "CRITICAL: Change SNMP community string from default 'public'/'private'. Consider SNMPv3 with authentication."),
    (lambda g: g.has_snmp,
     "Restrict SNMP access with ACLs — only allow trusted management hosts."),
    (lambda g: g.weak_tls,
     "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 minimum (prefer TLS 1.3)."),
    (lambda g: g.self_signed_cert,
     "Replace self-signed certificate with a CA-signed cert or use Let's Encrypt."),
    (lambda g: 80 in g.open_ports and 443 not in g.open_ports,
     "Enable HTTPS management and redirect HTTP to HTTPS. Disable plain HTTP admin."),
    (lambda g: 8291 in g.open_ports,
     "Disable or firewall Winbox port (8291). Use SSH or HTTPS instead."),
    (lambda g: 8728 in g.open_ports,
     "Disable RouterOS plaintext API port (8728). Use SSL API port (8729) with strong password."),
    (lambda g: 623 in g.open_ports,
     "Firewall IPMI/BMC port (623). IPMI has known unauthenticated vulnerabilities."),
    (lambda g: len(g.open_ports) > 6,
     f"Reduce attack surface: disable unnecessary services. Only essential management ports should be reachable."),
    (lambda g: 179 in g.open_ports,
     "Verify BGP peer authentication (MD5/TCP-AO) is configured on all peering sessions."),
    (lambda g: not g.routes_icmp and not g.routes_tcp,
     "Gateway does not appear to route external traffic. Verify it is an actual default gateway."),
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScoringEngine:
    """
    Compute all scores for a GatewayInfo and write them back in-place.
    Can be called after both FingerprintEngine and SecurityScanner have run.
    """

    def run(self, gw: GatewayInfo) -> None:
        gw.security_score     = self._security(gw)
        gw.exposure_score     = self._exposure(gw)
        gw.availability_score = self._availability(gw)
        gw.risk_level         = self._risk_level(gw)
        gw.recommendations    = self._recommendations(gw)

    # ── Security score (0–100, starts at 100 and deducts) ────────────────────

    def _security(self, gw: GatewayInfo) -> int:
        score = 100
        for penalty, label, condition in _SEC_PENALTIES:
            try:
                if condition(gw):
                    score -= penalty
            except Exception:
                pass
        return max(0, score)

    # ── Exposure score (0–100, accumulates from exposed services) ────────────

    def _exposure(self, gw: GatewayInfo) -> int:
        score = 0
        for port, weight in _EXPOSURE_WEIGHTS.items():
            if port in gw.open_ports:
                score += weight
        # Virtual gateways on the broadcast domain add exposure
        if gw.is_virtual:
            score += 10
        return min(100, score)

    # ── Availability score (0–100 based on routing confirmation) ─────────────

    def _availability(self, gw: GatewayInfo) -> int:
        score = 0
        if gw.routes_icmp:
            score += 50
        if gw.routes_tcp:
            score += 30
        if gw.response_time_ms > 0:
            score += 10
            # Bonus for low latency
            if gw.response_time_ms < 5:
                score += 10
        return min(100, score)

    # ── Risk level ────────────────────────────────────────────────────────────

    def _risk_level(self, gw: GatewayInfo) -> str:
        s = gw.security_score
        if s < 40:
            return "CRITICAL"
        if s < 60:
            return "HIGH"
        if s < 80:
            return "MEDIUM"
        return "LOW"

    # ── Recommendations ───────────────────────────────────────────────────────

    def _recommendations(self, gw: GatewayInfo) -> List[str]:
        recs = []
        for condition, text in _RECOMMENDATIONS:
            try:
                if condition(gw):
                    recs.append(text)
            except Exception:
                pass
        return recs
