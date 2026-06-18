"""
Gateway Finder - Network Utility Helpers
All functions handle their own exceptions and return safe defaults.
"""

from __future__ import annotations

import os
import re
import socket
import struct
import platform
import subprocess
import ipaddress
import logging
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ── Optional dependencies ────────────────────────────────────────────────────
try:
    import netifaces
    _NETIFACES = True
except ImportError:
    _NETIFACES = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Privilege helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def is_root() -> bool:
    """Return True if running with root / Administrator privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Validation helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


_MAC_RE = re.compile(
    r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$'
)

def is_valid_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac.strip()))


def normalize_mac(mac: str) -> str:
    """Return MAC in uppercase colon-separated format, or '' on error."""
    try:
        clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
        if len(clean) != 12:
            return ""
        return ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
    except Exception:
        return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Interface helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_local_interfaces() -> List[Dict]:
    """
    Return list of usable interfaces with their addresses.
    Falls back gracefully when netifaces is absent.
    Each dict: {name, ipv4, ipv4_mask, ipv6, mac, is_up}
    """
    interfaces: List[Dict] = []

    if _NETIFACES:
        for name in netifaces.interfaces():
            info: Dict = {"name": name, "ipv4": "", "ipv4_mask": "", "ipv6": [], "mac": "", "is_up": False}
            try:
                addrs = netifaces.ifaddresses(name)
                if netifaces.AF_INET in addrs:
                    a = addrs[netifaces.AF_INET][0]
                    info["ipv4"]      = a.get("addr", "")
                    info["ipv4_mask"] = a.get("netmask", "")
                    info["is_up"]     = bool(info["ipv4"])
                if netifaces.AF_INET6 in addrs:
                    info["ipv6"] = [
                        a.get("addr", "").split("%")[0]
                        for a in addrs[netifaces.AF_INET6]
                    ]
                if netifaces.AF_LINK in addrs:
                    info["mac"] = normalize_mac(addrs[netifaces.AF_LINK][0].get("addr", ""))
            except Exception as exc:
                log.debug("netifaces error on %s: %s", name, exc)
            if info["ipv4"] and not info["ipv4"].startswith("127."):
                interfaces.append(info)
        return interfaces

    # ── fallback: ip addr show ───────────────────────────────────────────────
    try:
        out = _run(["ip", "-o", "addr", "show"])
        for line in out.splitlines():
            m4 = re.search(r'(\S+)\s+inet\s+([\d.]+)/(\d+)', line)
            m6 = re.search(r'(\S+)\s+inet6\s+([\w:]+)/(\d+)', line)
            entry = None
            if m4:
                iface, ip4, prefix = m4.group(1), m4.group(2), m4.group(3)
                if ip4.startswith("127."):
                    continue
                entry = {"name": iface, "ipv4": ip4, "ipv4_mask": prefix,
                         "ipv6": [], "mac": "", "is_up": True}
            if entry:
                interfaces.append(entry)
    except Exception as exc:
        log.debug("ip addr fallback failed: %s", exc)

    return interfaces


def get_interface_ip(interface: str) -> str:
    """Return IPv4 address of interface, empty string on failure."""
    for iface in get_local_interfaces():
        if iface["name"] == interface:
            return iface["ipv4"]
    return ""


def get_interface_network(interface: str) -> str:
    """Return CIDR network for interface (e.g. 192.168.1.0/24), '' on fail."""
    for iface in get_local_interfaces():
        if iface["name"] == interface and iface["ipv4"]:
            try:
                net = ipaddress.ip_interface(
                    f"{iface['ipv4']}/{iface['ipv4_mask']}"
                ).network
                return str(net)
            except Exception:
                pass
    return ""


def pick_best_interface() -> str:
    """Return name of the best non-loopback interface with a valid IPv4."""
    prefer = ("eth0", "ens33", "ens3", "enp0s3", "wlan0", "wlp2s0")
    ifaces = get_local_interfaces()
    for name in prefer:
        for i in ifaces:
            if i["name"] == name:
                return name
    return ifaces[0]["name"] if ifaces else "eth0"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Gateway helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_default_gateways() -> List[Dict]:
    """
    Detect default gateway(s) via multiple platform-aware methods.
    Returns list of {ip, interface, family, method}.
    """
    gateways: List[Dict] = []

    # ── netifaces (most reliable) ────────────────────────────────────────────
    if _NETIFACES:
        try:
            gw = netifaces.gateways()
            for family, af in ((netifaces.AF_INET, "IPv4"), (netifaces.AF_INET6, "IPv6")):
                if family in gw.get("default", {}):
                    ip, iface = gw["default"][family][:2]
                    gateways.append({"ip": ip, "interface": iface, "family": af, "method": "netifaces"})
            if gateways:
                return gateways
        except Exception as exc:
            log.debug("netifaces gateways: %s", exc)

    # ── /proc/net/route (Linux) ──────────────────────────────────────────────
    if os.path.exists("/proc/net/route"):
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 8:
                        continue
                    iface  = parts[0]
                    dest   = int(parts[1], 16)
                    gw_raw = int(parts[2], 16)
                    flags  = int(parts[3], 16)
                    if dest == 0 and (flags & 0x2):          # UG flag = gateway
                        gw_ip = socket.inet_ntoa(struct.pack("<I", gw_raw))
                        gateways.append({"ip": gw_ip, "interface": iface, "family": "IPv4", "method": "proc_net_route"})
            if gateways:
                return gateways
        except Exception as exc:
            log.debug("/proc/net/route: %s", exc)

    # ── ip route (Linux/Unix) ────────────────────────────────────────────────
    try:
        out = _run(["ip", "route", "show", "default"])
        for line in out.splitlines():
            m = re.search(r'default via ([\d.]+)\s+dev\s+(\S+)', line)
            if m:
                gateways.append({"ip": m.group(1), "interface": m.group(2), "family": "IPv4", "method": "ip_route"})
        if gateways:
            return gateways
    except Exception:
        pass

    # ── netstat -nr (macOS / BSD) ────────────────────────────────────────────
    try:
        out = _run(["netstat", "-nr"])
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] in ("default", "0.0.0.0"):
                ip = parts[1] if len(parts) > 1 else ""
                if is_valid_ip(ip):
                    iface = parts[-1] if len(parts) > 3 else "unknown"
                    gateways.append({"ip": ip, "interface": iface, "family": "IPv4", "method": "netstat"})
        if gateways:
            return gateways
    except Exception:
        pass

    # ── route print (Windows) ────────────────────────────────────────────────
    if platform.system().lower() == "windows":
        try:
            out = _run(["route", "print", "0.0.0.0"])
            m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)', out)
            if m:
                gateways.append({"ip": m.group(1), "interface": "unknown", "family": "IPv4", "method": "route_print"})
        except Exception:
            pass

    # ── socket connect trick (last resort, only gets IP - no interface) ──────
    if not gateways:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 53))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            gw_guess = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            gateways.append({"ip": gw_guess, "interface": "unknown", "family": "IPv4", "method": "socket_guess", "low_confidence": True})
        except Exception:
            pass

    return gateways


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Network I/O helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def ping_host(ip: str, count: int = 1, timeout: int = 2) -> Tuple[bool, float]:
    """
    ICMP ping via subprocess. Returns (alive, avg_ms).
    Works on Linux, macOS, Windows.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", str(count), "-W", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        alive = result.returncode == 0
        ms = 0.0
        m = re.search(r'(?:avg|average)[^\d]*([\d.]+)', result.stdout, re.IGNORECASE)
        if not m:
            m = re.search(r'time[=<]([\d.]+)\s*ms', result.stdout, re.IGNORECASE)
        if m:
            ms = float(m.group(1))
        return alive, ms
    except subprocess.TimeoutExpired:
        return False, 0.0
    except Exception as exc:
        log.debug("ping_host %s: %s", ip, exc)
        return False, 0.0


def resolve_hostname(ip: str, timeout: int = 2) -> str:
    """Reverse DNS lookup. Returns hostname or empty string."""
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


def tcp_connect(ip: str, port: int, timeout: int = 2) -> bool:
    """Return True if TCP port is open (confirmed SYN-ACK)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def read_mac_file(filepath: str) -> List[Dict]:
    """
    Parse a MAC address file supporting multiple formats:
      00:11:22:33:44:55
      192.168.1.1  00:11:22:33:44:55
      00-11-22-33-44-55 192.168.1.1 (hostname)
    Returns list of {mac, ip} dicts.  Skips malformed lines silently.
    """
    _MAC = re.compile(r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}'
                      r'[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})')
    _IP  = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    entries: List[Dict] = []

    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m_mac = _MAC.search(line)
                if not m_mac:
                    continue
                mac = normalize_mac(m_mac.group(1))
                if not mac:
                    continue
                entry: Dict = {"mac": mac, "ip": ""}
                m_ip = _IP.search(line)
                if m_ip and is_valid_ip(m_ip.group(1)):
                    entry["ip"] = m_ip.group(1)
                entries.append(entry)
    except FileNotFoundError:
        log.error("MAC file not found: %s", filepath)
    except PermissionError:
        log.error("Cannot read MAC file (permission denied): %s", filepath)
    except Exception as exc:
        log.error("Error reading MAC file %s: %s", filepath, exc)

    return entries


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Internal helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _run(cmd: List[str], timeout: int = 6) -> str:
    """Run a subprocess and return stdout. Raises on non-zero exit."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout
