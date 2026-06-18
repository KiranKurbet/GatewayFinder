"""
Gateway Finder - Discovery Engine
Discovers gateways via ARP scanning, routing probes, virtual-gateway sniffing,
and MAC-file loading.  Every result carries a confidence level; only confirmed
results are surfaced to the CLI.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from gateway_finder.utils.helpers import (
    get_default_gateways, get_interface_network, is_root,
    normalize_mac, is_valid_ip, read_mac_file, ping_host,
    resolve_hostname, pick_best_interface,
)

log = logging.getLogger(__name__)

# ── Optional scapy ──────────────────────────────────────────────────────────
try:
    from scapy.all import (
        conf as scapy_conf,
        Ether, ARP, IP, TCP, ICMP, UDP,
        srp, sr1, sniff,
    )
    _SCAPY = True
except ImportError:
    _SCAPY = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data model
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}


@dataclass
class GatewayInfo:
    """All discovered and analysed data for one gateway candidate."""

    # ── Identity ────────────────────────────────────────────────────────────
    ip: str                   = ""
    mac: str                  = ""
    hostname: str             = ""
    interface: str            = ""

    # ── Discovery meta ──────────────────────────────────────────────────────
    is_default: bool          = False
    discovery_method: str     = ""
    confidence: str           = "low"   # low | medium | high | confirmed

    # ── Routing capability ──────────────────────────────────────────────────
    routes_icmp: bool         = False
    routes_tcp: bool          = False
    ttl_exceeded: bool        = False

    # ── Fingerprint (populated by FingerprintEngine) ─────────────────────
    vendor: str               = "Unknown"
    os_guess: str             = "Unknown"
    ttl: int                  = 0
    router_model: str         = ""
    fw_version: str           = ""
    management_url: str       = ""
    cloud_provider: str       = ""

    # ── Virtual gateway ──────────────────────────────────────────────────
    is_virtual: bool          = False
    virtual_protocol: str     = ""      # HSRP | VRRP | GLBP

    # ── Security scan (populated by SecurityScanner) ──────────────────────
    open_ports: List[int]     = field(default_factory=list)
    services: Dict[int, str]  = field(default_factory=dict)
    vulnerabilities: List[str]= field(default_factory=list)
    has_telnet: bool          = False
    has_snmp: bool            = False
    snmp_community: str       = ""
    weak_tls: bool            = False
    self_signed_cert: bool    = False

    # ── Scores (populated by ScoringEngine) ──────────────────────────────
    security_score: int       = -1   # -1 = not yet scored
    exposure_score: int       = -1
    availability_score: int   = -1
    risk_level: str           = "Unknown"
    recommendations: List[str]= field(default_factory=list)

    # ── Timing ──────────────────────────────────────────────────────────────
    response_time_ms: float   = 0.0

    def to_dict(self) -> Dict:
        return {
            "ip":                self.ip,
            "mac":               self.mac,
            "hostname":          self.hostname,
            "interface":         self.interface,
            "is_default":        self.is_default,
            "discovery_method":  self.discovery_method,
            "confidence":        self.confidence,
            "routes_icmp":       self.routes_icmp,
            "routes_tcp":        self.routes_tcp,
            "vendor":            self.vendor,
            "os_guess":          self.os_guess,
            "ttl":               self.ttl,
            "router_model":      self.router_model,
            "management_url":    self.management_url,
            "cloud_provider":    self.cloud_provider,
            "is_virtual":        self.is_virtual,
            "virtual_protocol":  self.virtual_protocol,
            "open_ports":        self.open_ports,
            "services":          self.services,
            "vulnerabilities":   self.vulnerabilities,
            "has_telnet":        self.has_telnet,
            "has_snmp":          self.has_snmp,
            "snmp_community":    self.snmp_community,
            "weak_tls":          self.weak_tls,
            "self_signed_cert":  self.self_signed_cert,
            "security_score":    self.security_score,
            "exposure_score":    self.exposure_score,
            "availability_score":self.availability_score,
            "risk_level":        self.risk_level,
            "recommendations":   self.recommendations,
            "response_time_ms":  self.response_time_ms,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Discovery engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DiscoveryEngine:
    """
    Orchestrates all gateway-discovery methods.

    Usage::

        engine = DiscoveryEngine(interface="eth0", timeout=3)
        gateways = engine.run()            # full auto-discovery
        # or step by step:
        gateways = engine.discover_defaults()
        gateways += engine.arp_scan()
        engine.probe_routing(gateways, target_ip="8.8.8.8")
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: int = 3,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.interface   = interface or pick_best_interface()
        self.timeout     = timeout
        self._progress   = progress_cb or (lambda msg: None)
        self._seen_ips: set = set()

    # ── Public orchestration ─────────────────────────────────────────────────

    def run(
        self,
        target_ip: str = "8.8.8.8",
        network: Optional[str] = None,
        mac_file: Optional[str] = None,
        probe_routing: bool = True,
        detect_virtual: bool = True,
    ) -> List[GatewayInfo]:
        """
        Full discovery pass. Returns only unique, confirmed gateways.
        """
        candidates: List[GatewayInfo] = []

        self._progress("Detecting default gateway…")
        candidates += self.discover_defaults()

        self._progress("Running ARP scan…")
        candidates += self.arp_scan(network=network)

        if mac_file:
            self._progress(f"Loading MACs from {mac_file}…")
            candidates += self.from_file(mac_file)

        if detect_virtual and is_root() and _SCAPY:
            self._progress("Sniffing for virtual gateways (HSRP/VRRP/GLBP)…")
            candidates += self.detect_virtual(timeout=8)

        # Deduplicate by IP
        unique: Dict[str, GatewayInfo] = {}
        for gw in candidates:
            if gw.ip not in unique:
                unique[gw.ip] = gw
            else:
                # Merge: keep higher-confidence entry, copy routing info
                existing = unique[gw.ip]
                if CONFIDENCE_RANK.get(gw.confidence, 0) > CONFIDENCE_RANK.get(existing.confidence, 0):
                    gw.routes_icmp = gw.routes_icmp or existing.routes_icmp
                    gw.routes_tcp  = gw.routes_tcp  or existing.routes_tcp
                    unique[gw.ip]  = gw
                else:
                    existing.routes_icmp = existing.routes_icmp or gw.routes_icmp
                    existing.routes_tcp  = existing.routes_tcp  or gw.routes_tcp

        result = list(unique.values())

        # Hostname resolution for all candidates
        for gw in result:
            if not gw.hostname and gw.ip:
                gw.hostname = resolve_hostname(gw.ip, timeout=2)

        if probe_routing and result:
            self._progress("Probing routing capability…")
            self.probe_routing(result, target_ip=target_ip)

        # Only return gateways with at least medium confidence
        return [gw for gw in result if CONFIDENCE_RANK.get(gw.confidence, 0) >= 1]

    # ── Discovery methods ────────────────────────────────────────────────────

    def discover_defaults(self) -> List[GatewayInfo]:
        """Detect the default gateway(s) from the OS routing table."""
        results: List[GatewayInfo] = []
        for entry in get_default_gateways():
            gw = GatewayInfo(
                ip               = entry["ip"],
                interface        = entry.get("interface", self.interface),
                is_default       = True,
                discovery_method = f"routing_table/{entry.get('method', 'unknown')}",
                confidence       = "low" if entry.get("low_confidence") else "high",
            )
            results.append(gw)
            log.debug("Default GW: %s via %s", gw.ip, entry.get("method"))
        return results

    def arp_scan(self, network: Optional[str] = None) -> List[GatewayInfo]:
        """
        ARP scan the local network.  Falls back to 'arp -a' when scapy/root
        not available.  Results have confidence=high (ARP reply confirmed).
        """
        target = network or get_interface_network(self.interface)
        if not target:
            log.warning("Cannot determine network for interface %s; skipping ARP scan.", self.interface)
            return []

        if _SCAPY and is_root():
            return self._arp_scan_scapy(target)
        return self._arp_scan_cache()

    def from_file(self, filepath: str) -> List[GatewayInfo]:
        """Load gateway candidates from a MAC-address file."""
        results: List[GatewayInfo] = []
        for entry in read_mac_file(filepath):
            mac = normalize_mac(entry.get("mac", ""))
            ip  = entry.get("ip", "")
            if not mac:
                continue
            gw = GatewayInfo(
                ip               = ip,
                mac              = mac,
                interface        = self.interface,
                discovery_method = "mac_file",
                confidence       = "medium" if ip else "low",
            )
            results.append(gw)
        log.info("Loaded %d entries from %s", len(results), filepath)
        return results

    def probe_routing(
        self,
        candidates: List[GatewayInfo],
        target_ip: str = "8.8.8.8",
    ) -> None:
        """
        Test whether each candidate actually routes packets to the internet.
        Uses TTL=1 probes (expect ICMP TTL-exceeded) and full-TTL probes.
        Modifies candidates in-place.
        Requires scapy + root; silently skips otherwise.
        """
        if not _SCAPY:
            log.warning("Scapy not available — routing probes skipped.")
            self._probe_routing_fallback(candidates, target_ip)
            return
        if not is_root():
            log.warning("Root required for routing probes — using ping fallback.")
            self._probe_routing_fallback(candidates, target_ip)
            return

        for gw in candidates:
            if not gw.mac:
                continue
            self._probe_single(gw, target_ip)

    def detect_virtual(self, timeout: int = 8) -> List[GatewayInfo]:
        """
        Passively sniff for HSRP / VRRP / GLBP hello packets.
        Returns GatewayInfo objects only for confirmed virtual gateways.
        Requires scapy + root.
        """
        if not _SCAPY or not is_root():
            return []

        results: List[GatewayInfo] = []
        seen: set = set()

        def _handle(pkt):
            try:
                ip_src = pkt[IP].src if pkt.haslayer(IP) else ""
                mac_src = pkt[Ether].src if pkt.haslayer(Ether) else ""
                mac_norm = normalize_mac(mac_src)

                proto = ""
                # VRRP — IP protocol 112
                if pkt.haslayer(IP) and pkt[IP].proto == 112:
                    proto = "VRRP"
                # HSRP — UDP/1985
                elif pkt.haslayer(UDP) and pkt[UDP].dport == 1985:
                    proto = "HSRP"
                # GLBP — UDP/3222
                elif pkt.haslayer(UDP) and pkt[UDP].dport == 3222:
                    proto = "GLBP"

                if proto and ip_src and ip_src not in seen:
                    seen.add(ip_src)
                    results.append(GatewayInfo(
                        ip               = ip_src,
                        mac              = mac_norm,
                        interface        = self.interface,
                        is_virtual       = True,
                        virtual_protocol = proto,
                        discovery_method = "passive_sniff",
                        confidence       = "confirmed",
                    ))
                    log.debug("Virtual GW detected: %s (%s)", ip_src, proto)
            except Exception as exc:
                log.debug("_handle pkt error: %s", exc)

        try:
            sniff(
                iface   = self.interface,
                prn     = _handle,
                timeout = timeout,
                store   = 0,
                filter  = "udp port 1985 or udp port 3222 or ip proto 112",
            )
        except Exception as exc:
            log.error("Virtual GW sniff failed: %s", exc)

        return results

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _arp_scan_scapy(self, target: str) -> List[GatewayInfo]:
        results: List[GatewayInfo] = []
        try:
            scapy_conf.verb = 0
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = srp(pkt, iface=self.interface, timeout=self.timeout, verbose=0)
            for _, rcv in answered:
                gw = GatewayInfo(
                    ip               = rcv[ARP].psrc,
                    mac              = normalize_mac(rcv[Ether].src),
                    interface        = self.interface,
                    discovery_method = "arp_scan",
                    confidence       = "confirmed",
                )
                results.append(gw)
                log.debug("ARP: %s  %s", gw.ip, gw.mac)
        except Exception as exc:
            log.error("Scapy ARP scan error: %s", exc)
        return results

    def _arp_scan_cache(self) -> List[GatewayInfo]:
        """Parse OS ARP cache as a last resort — confidence=medium."""
        import subprocess, re
        results: List[GatewayInfo] = []
        _MAC = re.compile(r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}'
                          r'[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})')
        _IP  = re.compile(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})')
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                m_ip  = _IP.search(line)
                m_mac = _MAC.search(line)
                if m_ip and m_mac and is_valid_ip(m_ip.group(1)):
                    ip  = m_ip.group(1)
                    mac = normalize_mac(m_mac.group(1))
                    if ip.startswith("127.") or ip.endswith(".255") or not mac:
                        continue
                    results.append(GatewayInfo(
                        ip               = ip,
                        mac              = mac,
                        interface        = self.interface,
                        discovery_method = "arp_cache",
                        confidence       = "medium",
                    ))
        except Exception as exc:
            log.debug("ARP cache parse error: %s", exc)
        return results

    def _probe_single(self, gw: GatewayInfo, target_ip: str) -> None:
        """Send ICMP and TCP probes through one candidate gateway."""
        mac = gw.mac
        iface = self.interface

        # ── ICMP TTL=1 → expect TTL-exceeded ────────────────────────────────
        try:
            pkt = Ether(dst=mac) / IP(dst=target_ip, ttl=1) / ICMP(seq=1)
            ans, _ = srp(pkt, iface=iface, timeout=self.timeout, verbose=0)
            if ans:
                gw.routes_icmp  = True
                gw.ttl_exceeded = True
                gw.confidence   = "confirmed"
        except Exception as exc:
            log.debug("ICMP TTL=1 probe %s: %s", gw.ip, exc)

        # ── ICMP full TTL → expect echo-reply ───────────────────────────────
        if not gw.routes_icmp:
            try:
                t0  = time.monotonic()
                pkt = Ether(dst=mac) / IP(dst=target_ip) / ICMP(seq=2)
                ans, _ = srp(pkt, iface=iface, timeout=self.timeout, verbose=0)
                if ans:
                    gw.routes_icmp      = True
                    gw.response_time_ms = round((time.monotonic() - t0) * 1000, 2)
                    gw.confidence       = "confirmed"
            except Exception as exc:
                log.debug("ICMP probe %s: %s", gw.ip, exc)

        # ── TCP SYN/TTL=1 → expect TTL-exceeded ────────────────────────────
        try:
            pkt = Ether(dst=mac) / IP(dst=target_ip, ttl=1) / TCP(dport=80, flags="S", seq=100)
            ans, _ = srp(pkt, iface=iface, timeout=self.timeout, verbose=0)
            if ans:
                gw.routes_tcp = True
                gw.confidence = "confirmed"
        except Exception as exc:
            log.debug("TCP TTL=1 probe %s: %s", gw.ip, exc)

    def _probe_routing_fallback(
        self, candidates: List[GatewayInfo], target_ip: str
    ) -> None:
        """
        When scapy/root is not available, verify each gateway is reachable
        with a plain ICMP ping.  Only marks routes_icmp=True on confirmed reply.
        """
        for gw in candidates:
            alive, ms = ping_host(gw.ip, count=2, timeout=self.timeout)
            if alive:
                gw.routes_icmp      = True
                gw.response_time_ms = ms
                if gw.confidence == "low":
                    gw.confidence = "medium"
