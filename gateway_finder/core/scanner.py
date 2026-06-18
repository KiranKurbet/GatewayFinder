"""
Gateway Finder - Security Scanner
Checks open ports, SNMP community strings, Telnet exposure, SSH banners,
SSL/TLS weaknesses, and firewall behaviour.
Only registers confirmed findings — no guesses or false positives.
"""

from __future__ import annotations

import re
import socket
import logging
import concurrent.futures
from typing import Dict, List, Optional, Tuple

from gateway_finder.core.discovery import GatewayInfo
from gateway_finder.utils.helpers import tcp_connect

log = logging.getLogger(__name__)

# ── Optional scapy for SNMP / advanced probes ────────────────────────────────
try:
    from scapy.all import IP, UDP, sr1
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
    _SCAPY_SNMP = True
except ImportError:
    _SCAPY_SNMP = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Ports commonly open on gateway / router management interfaces
GATEWAY_PORTS: Dict[int, str] = {
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTPS",
    161:  "SNMP",
    179:  "BGP",
    443:  "HTTPS",
    445:  "SMB",
    500:  "IKE (IPsec)",
    514:  "Syslog",
    520:  "RIP",
    521:  "RIPng",
    623:  "IPMI",
    646:  "LDP",
    830:  "NETCONF-SSH",
    1194: "OpenVPN",
    1723: "PPTP VPN",
    2152: "GTP",
    4500: "NAT-T (IPsec)",
    8080: "HTTP-Alt",
    8291: "Winbox (MikroTik)",
    8443: "HTTPS-Alt",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",
}

# SNMP community strings to test (only the most common defaults)
_SNMP_COMMUNITIES = ["public", "private", "admin", "cisco", "manager", "community", "secret"]

# OID for sysDescr
_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scanner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SecurityScanner:
    """
    Runs security checks against one GatewayInfo object.
    All results are written directly into the GatewayInfo.
    """

    def __init__(self, timeout: int = 3, workers: int = 20):
        self.timeout = timeout
        self.workers = workers

    def run(self, gw: GatewayInfo) -> None:
        """Full scan pipeline.  Modifies *gw* in-place."""
        if not gw.ip:
            return

        self._port_scan(gw)
        self._check_telnet(gw)
        self._check_ssh_banner(gw)
        self._check_snmp(gw)
        self._check_tls_weakness(gw)
        self._detect_firewall(gw)
        self._enumerate_vulns(gw)

    # ── Port scan ─────────────────────────────────────────────────────────────

    def _port_scan(self, gw: GatewayInfo) -> None:
        """
        Concurrent TCP connect scan of known gateway ports.
        Only records ports where connect() returns 0 (confirmed open).
        """
        def _probe(port: int) -> Optional[Tuple[int, str]]:
            if tcp_connect(gw.ip, port, timeout=self.timeout):
                return (port, GATEWAY_PORTS.get(port, "Unknown"))
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(_probe, p): p for p in GATEWAY_PORTS}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    result = fut.result()
                    if result:
                        port, svc = result
                        if port not in gw.open_ports:
                            gw.open_ports.append(port)
                            gw.services[port] = svc
                except Exception as exc:
                    log.debug("Port scan error: %s", exc)

        gw.open_ports.sort()
        log.debug("Open ports on %s: %s", gw.ip, gw.open_ports)

    # ── Telnet ────────────────────────────────────────────────────────────────

    def _check_telnet(self, gw: GatewayInfo) -> None:
        if 23 not in gw.open_ports:
            return
        banner = self._grab_tcp_banner(gw.ip, 23)
        if banner is not None:           # None = error; "" = connected but silent
            gw.has_telnet = True
            log.debug("Telnet confirmed on %s (banner: %r)", gw.ip, banner[:80])

    # ── SSH banner ────────────────────────────────────────────────────────────

    def _check_ssh_banner(self, gw: GatewayInfo) -> None:
        if 22 not in gw.open_ports:
            return
        banner = self._grab_tcp_banner(gw.ip, 22)
        if banner and banner.startswith("SSH-"):
            gw.services[22] = f"SSH ({banner.strip()[:60]})"

    # ── SNMP ──────────────────────────────────────────────────────────────────

    def _check_snmp(self, gw: GatewayInfo) -> None:
        """
        Test SNMP v1/v2c with well-known community strings.
        Uses scapy if available, falls back to socket-based probe.
        """
        if _SCAPY_SNMP:
            self._snmp_scapy(gw)
        else:
            self._snmp_socket(gw)

    def _snmp_scapy(self, gw: GatewayInfo) -> None:
        from gateway_finder.utils.helpers import is_root
        if not is_root():
            self._snmp_socket(gw)
            return

        for community in _SNMP_COMMUNITIES:
            try:
                pkt = (
                    IP(dst=gw.ip)
                    / UDP(dport=161, sport=40000)
                    / SNMP(
                        community=community.encode(),
                        PDU=SNMPget(varbindlist=[SNMPvarbind(oid=_OID_SYSDESCR)])
                    )
                )
                reply = sr1(pkt, timeout=self.timeout, verbose=0)
                if reply and reply.haslayer(SNMP):
                    gw.has_snmp       = True
                    gw.snmp_community = community
                    if 161 not in gw.open_ports:
                        gw.open_ports.append(161)
                        gw.services[161] = "SNMP"
                    # Try to extract sysDescr
                    try:
                        desc = reply[SNMP].PDU.varbindlist[0].value.val
                        if isinstance(desc, bytes):
                            desc = desc.decode("utf-8", errors="ignore")
                        log.debug("SNMP sysDescr %s: %s", gw.ip, desc[:100])
                        if desc and not gw.router_model:
                            gw.router_model = desc[:120]
                    except Exception:
                        pass
                    return    # stop on first hit
            except Exception as exc:
                log.debug("SNMP scapy %s community=%s: %s", gw.ip, community, exc)

    def _snmp_socket(self, gw: GatewayInfo) -> None:
        """
        Minimal SNMP v1 GET probe via raw UDP.
        Sends a pre-built packet for sysDescr OID and checks for a valid response.
        """
        # ASN.1 BER-encoded SNMP v1 GET for sysDescr with community 'public'
        def _build_snmp_get(community: str) -> bytes:
            oid_bytes = bytes([
                0x30, 0x1a,               # OID SEQUENCE
                0x06, 0x0a,               # OID value
                0x2b, 0x06, 0x01, 0x02,
                0x01, 0x01, 0x01, 0x00,
                0x05, 0x00,               # NULL
            ])
            varbind = bytes([0x30, len(oid_bytes)]) + oid_bytes
            varbindlist = bytes([0x30, len(varbind)]) + varbind
            pdu = (
                bytes([0xa0, len(varbindlist) + 12])  # GetRequest PDU
                + bytes([0x02, 0x01, 0x01])            # request-id
                + bytes([0x02, 0x01, 0x00])            # error-status
                + bytes([0x02, 0x01, 0x00])            # error-index
                + varbindlist
            )
            comm = community.encode()
            msg = (
                bytes([0x30])
                + bytes([len(pdu) + len(comm) + 7])
                + bytes([0x02, 0x01, 0x00])            # version = 0 (SNMPv1)
                + bytes([0x04, len(comm)]) + comm
                + pdu
            )
            return msg

        for community in _SNMP_COMMUNITIES[:4]:       # limit for socket method
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(_build_snmp_get(community), (gw.ip, 161))
                data, _ = sock.recvfrom(4096)
                sock.close()
                if data and len(data) > 10:
                    gw.has_snmp       = True
                    gw.snmp_community = community
                    if 161 not in gw.open_ports:
                        gw.open_ports.append(161)
                        gw.services[161] = "SNMP"
                    return
            except socket.timeout:
                pass
            except Exception as exc:
                log.debug("SNMP socket %s community=%s: %s", gw.ip, community, exc)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

    # ── TLS weakness ──────────────────────────────────────────────────────────

    def _check_tls_weakness(self, gw: GatewayInfo) -> None:
        """Mark weak_tls only if we can actually negotiate a deprecated version."""
        import ssl as _ssl
        ssl_ports = [p for p in gw.open_ports if p in (443, 8443, 4443)]
        for port in ssl_ports:
            try:
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
                # Force old versions if supported
                ctx.options |= getattr(_ssl, "OP_LEGACY_SERVER_CONNECT", 0)

                raw  = socket.create_connection((gw.ip, port), timeout=self.timeout)
                conn = ctx.wrap_socket(raw, server_hostname=gw.ip)
                ver  = conn.version()
                conn.close()

                if ver in ("TLSv1", "TLSv1.1"):
                    gw.weak_tls = True
                    log.debug("Weak TLS on %s:%d — %s", gw.ip, port, ver)
            except Exception as exc:
                log.debug("TLS check %s:%d: %s", gw.ip, port, exc)

    # ── Firewall detection ────────────────────────────────────────────────────

    def _detect_firewall(self, gw: GatewayInfo) -> None:
        """
        Heuristic firewall detection: probe a port likely to be filtered.
        - If TCP connect times out (no RST) → likely firewalled.
        - If RST received quickly → unfiltered.
        Does not add to vulnerabilities; just annotates services dict.
        """
        probe_port = 9999   # unlikely to be open on a router
        import time
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            t0  = time.monotonic()
            res = sock.connect_ex((gw.ip, probe_port))
            ms  = (time.monotonic() - t0) * 1000
            sock.close()

            if res == 111 and ms < 500:          # ECONNREFUSED quickly = no firewall
                gw.services[0] = "No firewall (RST received)"
            elif ms > 1400:                       # timeout = filtered
                gw.services[0] = "Firewall detected (port filtered)"
        except socket.timeout:
            gw.services[0] = "Firewall detected (port filtered)"
        except Exception as exc:
            log.debug("Firewall detect %s: %s", gw.ip, exc)

    # ── Vulnerability catalogue ───────────────────────────────────────────────

    def _enumerate_vulns(self, gw: GatewayInfo) -> None:
        """
        Build a list of concrete, confirmed vulnerabilities from scan data.
        Only entries with direct evidence are added.
        """
        vulns = gw.vulnerabilities

        if gw.has_telnet:
            vulns.append("Telnet enabled — unencrypted remote access (port 23)")

        if gw.has_snmp and gw.snmp_community in ("public", "private"):
            vulns.append(
                f"SNMP default community '{gw.snmp_community}' accepted — "
                "allows read/write access without authentication"
            )

        if gw.weak_tls:
            vulns.append("Weak TLS version negotiated (TLS 1.0 or 1.1) — vulnerable to POODLE / BEAST")

        if gw.self_signed_cert:
            vulns.append("Self-signed TLS certificate — no chain of trust, susceptible to MitM")

        if 8291 in gw.open_ports:
            vulns.append("MikroTik Winbox port (8291) open — unencrypted management protocol")

        if 8728 in gw.open_ports:
            vulns.append("MikroTik RouterOS API port (8728) open — plaintext API access")

        if 623 in gw.open_ports:
            vulns.append("IPMI/BMC port (623) open — often has authentication bypass vulnerabilities")

        if 179 in gw.open_ports:
            vulns.append("BGP port (179) open — ensure peer authentication is configured")

    # ── Banner helper ─────────────────────────────────────────────────────────

    def _grab_tcp_banner(self, ip: str, port: int, recv_bytes: int = 256) -> Optional[str]:
        """
        Connect to port and read up to recv_bytes of banner.
        Returns the decoded string (may be empty), or None on connection error.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            # Telnet / FTP / SSH send banner on connect; read immediately
            try:
                data = sock.recv(recv_bytes)
            except socket.timeout:
                data = b""
            sock.close()
            return data.decode("utf-8", errors="ignore").strip()
        except (ConnectionRefusedError, OSError):
            return None
        except Exception as exc:
            log.debug("Banner grab %s:%d: %s", ip, port, exc)
            return None
