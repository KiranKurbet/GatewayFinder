"""
Gateway Finder - Fingerprint Engine
Identifies vendor, OS, firmware hints via MAC OUI, TTL analysis,
HTTP response headers, and SSL/TLS certificate inspection.
Only sets fields when data is actually confirmed.
"""

from __future__ import annotations

import re
import socket
import ssl
import logging
import time
from typing import Dict, Optional

from gateway_finder.core.discovery import GatewayInfo
from gateway_finder.utils.helpers import tcp_connect, normalize_mac

log = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OUI → Vendor table  (network devices only — trimmed for size)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_OUI: Dict[str, str] = {
    # Cisco
    "00:00:0C": "Cisco", "00:1A:A1": "Cisco", "00:1A:A2": "Cisco",
    "00:1B:54": "Cisco", "00:1C:58": "Cisco", "00:1D:45": "Cisco",
    "00:1E:13": "Cisco", "00:1F:26": "Cisco", "00:21:A0": "Cisco",
    "00:22:90": "Cisco", "00:23:33": "Cisco", "00:24:13": "Cisco",
    "00:25:83": "Cisco", "00:26:CB": "Cisco", "04:6C:9D": "Cisco",
    "10:8C:CF": "Cisco", "1C:17:D3": "Cisco", "20:37:06": "Cisco",
    "28:6F:7F": "Cisco", "2C:4F:52": "Cisco", "34:DB:FD": "Cisco",
    "38:ED:18": "Cisco", "40:55:39": "Cisco", "44:47:CC": "Cisco",
    "48:F8:B3": "Cisco", "4C:77:6D": "Cisco", "50:06:04": "Cisco",
    "54:78:1A": "Cisco", "58:8D:09": "Cisco", "5C:5A:C7": "Cisco",
    "60:45:BD": "Cisco", "64:9E:F3": "Cisco", "6C:41:6A": "Cisco",
    "70:81:05": "Cisco", "74:86:7A": "Cisco", "78:72:5D": "Cisco",
    "84:B8:02": "Cisco", "88:43:E1": "Cisco", "8C:60:4F": "Cisco",
    "90:8D:6C": "Cisco", "94:0C:6D": "Cisco", "9C:AF:CA": "Cisco",
    "A0:E0:AF": "Cisco", "A4:4C:11": "Cisco", "A8:9D:21": "Cisco",
    "AC:F2:C5": "Cisco", "B0:AA:77": "Cisco", "B4:A4:E3": "Cisco",
    "B8:38:61": "Cisco", "C8:00:84": "Cisco", "CC:98:91": "Cisco",
    "D0:C2:82": "Cisco", "D4:8C:B5": "Cisco", "E8:BA:70": "Cisco",
    "EC:30:91": "Cisco", "F8:7B:20": "Cisco",
    # Juniper
    "00:10:DB": "Juniper", "00:12:1E": "Juniper", "00:19:E2": "Juniper",
    "00:21:59": "Juniper", "00:22:83": "Juniper", "28:C0:DA": "Juniper",
    "2C:6B:F5": "Juniper", "3C:61:04": "Juniper", "40:B4:F0": "Juniper",
    "48:22:54": "Juniper", "54:E0:32": "Juniper", "64:87:88": "Juniper",
    "78:FE:3D": "Juniper", "8C:60:4F": "Juniper", "AC:87:A3": "Juniper",
    # MikroTik
    "00:0C:42": "MikroTik", "18:FD:74": "MikroTik", "2C:C8:1B": "MikroTik",
    "48:8F:5A": "MikroTik", "4C:5E:0C": "MikroTik", "6C:3B:6B": "MikroTik",
    "74:4D:28": "MikroTik", "B8:69:F4": "MikroTik", "CC:2D:E0": "MikroTik",
    "D4:CA:6D": "MikroTik", "DC:2C:6E": "MikroTik", "E4:8D:8C": "MikroTik",
    # Fortinet
    "00:09:0F": "Fortinet", "00:0C:E6": "Fortinet", "70:4C:A5": "Fortinet",
    "08:5B:0E": "Fortinet", "0C:5A:DC": "Fortinet", "10:BE:F5": "Fortinet",
    "AC:1F:6B": "Fortinet", "B8:AC:6F": "Fortinet", "F4:DB:E6": "Fortinet",
    # Palo Alto Networks
    "00:1B:17": "Palo Alto Networks", "08:30:6B": "Palo Alto Networks",
    "DC:F7:19": "Palo Alto Networks",
    # Sophos
    "00:1A:8C": "Sophos", "3C:08:F6": "Sophos",
    # SonicWall
    "00:06:B1": "SonicWall", "C0:EA:E4": "SonicWall",
    # Check Point
    "00:1C:7F": "Check Point",
    # WatchGuard
    "00:90:7F": "WatchGuard",
    # Ubiquiti
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti", "18:E8:29": "Ubiquiti",
    # HP / Aruba
    "00:0B:0D": "HP Aruba", "00:0D:9D": "HP Aruba", "24:DE:C6": "HP Aruba",
    "40:B6:88": "HP Aruba", "84:18:88": "HP Aruba", "94:B4:0F": "HP Aruba",
    "C4:51:BE": "HP Aruba", "D8:C7:C8": "HP Aruba",
    # Huawei
    "00:18:82": "Huawei", "00:1E:10": "Huawei", "04:BD:88": "Huawei",
    "6C:8D:C1": "Huawei", "8C:0D:76": "Huawei", "AC:4E:91": "Huawei",
    # VMware virtual
    "00:0C:29": "VMware (Virtual)", "00:50:56": "VMware (Virtual)",
    "00:05:69": "VMware (Virtual)",
    # VirtualBox virtual
    "08:00:27": "VirtualBox (Virtual)",
    # QEMU/KVM virtual
    "52:54:00": "QEMU/KVM (Virtual)",
}

# Virtual-gateway MAC prefixes
_VIRTUAL_MAC = {
    "00:00:0C:07:AC": "Cisco HSRP",
    "00:00:5E:00:01": "IANA VRRP",
    "00:07:B4":        "Cisco GLBP",
}

# TTL → initial TTL → OS mapping
_TTL_MAP = [
    (255, 255, "Cisco IOS / Juniper JunOS / Network OS"),
    (254, 255, "Cisco IOS (classic)"),
    (128, 128, "Windows"),
    (127, 128, "Windows"),
    (64,  64,  "Linux / Android / macOS / FreeBSD"),
    (63,  64,  "Linux / macOS"),
    (60,  60,  "Solaris / AIX"),
    (32,  32,  "Windows 95/98/NT"),
]

# HTTP server/title fragments → vendor
_HTTP_SIGS = {
    "routeros":     "MikroTik RouterOS",
    "mikrotik":     "MikroTik",
    "cisco":        "Cisco",
    "juniper":      "Juniper",
    "fortinet":     "Fortinet",
    "fortigate":    "Fortinet FortiGate",
    "forti":        "Fortinet",
    "palo alto":    "Palo Alto Networks",
    "opnsense":     "OPNsense",
    "pfsense":      "pfSense",
    "openwrt":      "OpenWrt",
    "luci":         "OpenWrt (LuCI)",
    "dd-wrt":       "DD-WRT",
    "tomato":       "Tomato",
    "ubiquiti":     "Ubiquiti",
    "unifi":        "Ubiquiti UniFi",
    "edgeos":       "Ubiquiti EdgeOS",
    "sophos":       "Sophos",
    "checkpoint":   "Check Point",
    "sonicwall":    "SonicWall",
    "watchguard":   "WatchGuard",
    "zyxel":        "ZyXEL",
    "draytek":      "DrayTek",
    "avm":          "AVM FRITZ!Box",
    "fritz":        "AVM FRITZ!Box",
    "netgear":      "Netgear",
    "tp-link":      "TP-Link",
    "tplink":       "TP-Link",
    "d-link":       "D-Link",
    "asus":         "Asus",
    "linksys":      "Linksys",
    "huawei":       "Huawei",
}

# Cloud provider IP prefix hints (first 2 octets)
_CLOUD_HINTS = {
    "3.":    "AWS",  "13.": "AWS/Azure", "18.": "AWS",  "34.": "GCP/AWS",
    "35.":   "GCP",  "40.": "Azure",     "52.": "AWS",  "54.": "AWS",
    "20.":   "Azure","104.16.": "Cloudflare", "104.17.": "Cloudflare",
    "172.64.": "Cloudflare",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class FingerprintEngine:
    """Enrich a GatewayInfo with vendor, OS, and service fingerprints."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def run(self, gw: GatewayInfo) -> None:
        """Run all fingerprinting passes on *gw*, modifying it in-place."""
        if gw.mac:
            vendor = self._vendor_from_mac(gw.mac)
            if vendor:
                gw.vendor = vendor

        self._ttl_os(gw)
        self._http_probe(gw)
        self._ssl_probe(gw)
        self._cloud_detect(gw)

    # ── MAC → Vendor ─────────────────────────────────────────────────────────

    def _vendor_from_mac(self, mac: str) -> str:
        """Return vendor from OUI table or empty string."""
        mac = normalize_mac(mac)
        if not mac:
            return ""

        # Virtual gateway check
        for prefix, name in _VIRTUAL_MAC.items():
            if mac.upper().startswith(prefix):
                return name

        # 3-octet OUI
        oui = ":".join(mac.split(":")[:3])
        if oui in _OUI:
            return _OUI[oui]

        # 2-octet prefix scan
        prefix2 = ":".join(mac.split(":")[:2])
        for key, vendor in _OUI.items():
            if key.startswith(prefix2):
                return vendor

        return ""

    # ── TTL → OS ──────────────────────────────────────────────────────────────

    def _ttl_os(self, gw: GatewayInfo) -> None:
        """Try ICMP ping and fingerprint the TTL."""
        try:
            from scapy.all import IP, ICMP, sr1
            pkt   = IP(dst=gw.ip) / ICMP()
            reply = sr1(pkt, timeout=self.timeout, verbose=0)
            if reply and reply.haslayer(IP):
                ttl       = reply[IP].ttl
                gw.ttl    = ttl
                gw.os_guess = self._map_ttl(ttl)
                return
        except Exception:
            pass

        # Subprocess fallback
        import subprocess, platform as _plat
        system = _plat.system().lower()
        cmd    = (["ping", "-n", "1", gw.ip] if system == "windows"
                  else ["ping", "-c", "1", "-W", "2", gw.ip])
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            m   = re.search(r'ttl=(\d+)', out, re.IGNORECASE)
            if m:
                ttl          = int(m.group(1))
                gw.ttl       = ttl
                gw.os_guess  = self._map_ttl(ttl)
        except Exception as exc:
            log.debug("TTL ping fallback %s: %s", gw.ip, exc)

    @staticmethod
    def _map_ttl(ttl: int) -> str:
        for received, _, label in _TTL_MAP:
            if abs(ttl - received) <= 5:
                return label
        return f"Unknown (TTL {ttl})"

    # ── HTTP probe ────────────────────────────────────────────────────────────

    def _http_probe(self, gw: GatewayInfo) -> None:
        """Try HTTP/HTTPS on common management ports."""
        probes = [(80, False), (443, True), (8080, False), (8443, True)]
        for port, use_ssl in probes:
            if not tcp_connect(gw.ip, port, timeout=self.timeout):
                continue
            info = self._http_get(gw.ip, port, use_ssl)
            if not info:
                continue

            server = info.get("server", "")
            title  = info.get("title",  "")
            combined = (server + " " + title).lower()

            # Vendor detection
            if gw.vendor == "Unknown":
                for sig, vendor in _HTTP_SIGS.items():
                    if sig in combined:
                        gw.vendor = vendor
                        break

            # Management URL
            proto = "https" if use_ssl else "http"
            gw.management_url = f"{proto}://{gw.ip}:{port}/"

            # Model hint from title
            if title and not gw.router_model:
                gw.router_model = title[:80]

            log.debug("HTTP %s:%d → server=%s title=%s", gw.ip, port, server, title)
            break   # first successful probe is enough

    def _http_get(self, ip: str, port: int, use_ssl: bool) -> Optional[Dict]:
        """Raw HTTP GET /.  Returns {server, title, status_code} or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)

            sock.connect((ip, port))
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: GatewayFinder/2.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(req.encode())

            buf = b""
            try:
                while len(buf) < 16384:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except Exception:
                pass
            finally:
                sock.close()

            text = buf.decode("utf-8", errors="ignore")
            headers, _, body = text.partition("\r\n\r\n")
            header_lines = headers.splitlines()

            status_code = 0
            m = re.match(r'HTTP/\S+\s+(\d+)', header_lines[0]) if header_lines else None
            if m:
                status_code = int(m.group(1))

            server = ""
            for line in header_lines[1:]:
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break

            title = ""
            tm = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
            if tm:
                title = re.sub(r'\s+', ' ', tm.group(1)).strip()[:100]

            return {"server": server, "title": title, "status_code": status_code}

        except Exception as exc:
            log.debug("HTTP probe %s:%d: %s", ip, port, exc)
            return None

    # ── SSL probe ─────────────────────────────────────────────────────────────

    def _ssl_probe(self, gw: GatewayInfo) -> None:
        """Inspect TLS version and cert.  Sets weak_tls / self_signed_cert."""
        for port in (443, 8443, 4443):
            if not tcp_connect(gw.ip, port, timeout=self.timeout):
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                # Disable secure renegotiation to allow older TLS
                ctx.options       |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
                ctx.minimum_version = ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else ssl.TLSVersion.TLSv1

                raw  = socket.create_connection((gw.ip, port), timeout=self.timeout)
                conn = ctx.wrap_socket(raw, server_hostname=gw.ip)

                ver  = conn.version()
                cert = conn.getpeercert(binary_form=False)
                conn.close()

                if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                    gw.weak_tls = True

                if cert:
                    subj   = dict(x[0] for x in cert.get("subject",  []))
                    issuer = dict(x[0] for x in cert.get("issuer",   []))
                    cn_s   = subj.get("commonName",   "")
                    cn_i   = issuer.get("commonName", cn_s)
                    gw.self_signed_cert = (cn_s == cn_i or not cn_i)

                log.debug("SSL %s:%d ver=%s self_signed=%s", gw.ip, port, ver, gw.self_signed_cert)
                break

            except ssl.SSLError as exc:
                log.debug("SSL probe %s:%d SSLError: %s", gw.ip, port, exc)
            except Exception as exc:
                log.debug("SSL probe %s:%d: %s", gw.ip, port, exc)

    # ── Cloud detection ───────────────────────────────────────────────────────

    def _cloud_detect(self, gw: GatewayInfo) -> None:
        if not gw.ip:
            return
        for prefix, provider in _CLOUD_HINTS.items():
            if gw.ip.startswith(prefix):
                gw.cloud_provider = provider
                return
