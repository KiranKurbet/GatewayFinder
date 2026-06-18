#  GatewayFinder — Gateway Intelligence Engine

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-brightgreen?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/use-Authorized%20Only-red?style=for-the-badge"/>
</p>

> A professional CLI tool for **network gateway discovery**, **security assessment**, and **real-time monitoring** — built for penetration testers, red teamers, and network defenders.

---

##  Legal Disclaimer

This tool is intended **exclusively for authorized security testing and network administration**.  
Using GatewayFinder against networks you do not own or have explicit written permission to test is **illegal**.  
The author assumes no liability for misuse.

---

##  Features

###  Gateway Discovery
- Automatic default gateway detection (cross-platform)
- ARP-based subnet scanning (scapy or `arp -a` fallback)
- ICMP + TCP routing probes (TTL=1 and full-path)
- MAC address file loading (original `gateway-finder` mode)
- Passive HSRP / VRRP / GLBP virtual gateway sniffing

###  Fingerprinting
- MAC OUI → vendor identification (Cisco, Juniper, MikroTik, Fortinet, Palo Alto, Ubiquiti, Huawei, and more)
- TTL-based OS fingerprinting (Windows / Linux / Cisco IOS / JunOS)
- HTTP/HTTPS response analysis (server headers, page title)
- SSL/TLS version detection
- Management interface URL detection
- Cloud provider hint detection (AWS, Azure, GCP, Cloudflare)

###  Security Assessment
- Concurrent port scan of 20+ gateway-relevant ports
- SNMP community string probing (v1/v2c)
- Telnet exposure detection with banner grab
- SSH version banner capture
- SSL/TLS weakness detection (TLS 1.0/1.1)
- Self-signed certificate detection
- Firewall presence heuristic
- Confirmed vulnerability list (zero false positives)

###  Intelligence Scoring
Every discovered gateway receives:

| Score | Range | Meaning |
|-------|-------|---------|
| **Security Score** | 0–100 | Starts at 100; deducts per confirmed vulnerability |
| **Exposure Score** | 0–100 | Accumulates from exposed services |
| **Availability Score** | 0–100 | Based on confirmed routing + latency |
| **Risk Level** | LOW / MEDIUM / HIGH / CRITICAL | Derived from security score |

Actionable recommendations are generated for every detected issue.

###  Real-Time Monitoring
- Continuous ICMP ping loop
- Rolling latency statistics (avg, min, max, jitter)
- Packet loss tracking
- Alert callbacks for UP/DOWN transitions and high latency
- Event log with timestamps

###  Reporting
Export results as:
- **JSON** — machine-readable, suitable for pipeline integration
- **CSV** — spreadsheet/SIEM import
- **HTML** — dark-theme, self-contained professional report

---

##  Installation

### From source (recommended)
```bash
git clone https://github.com/KiranKurbet/GatewayFinder.git
cd GatewayFinder
pip install -e .
```

### Quick install
```bash
pip install gateway-finder
```

### Docker
```bash
docker build -t gatewayfinder .
docker run --rm --network=host --privileged gatewayfinder scan
```

> **Root / sudo is required** for ARP scanning, routing probes, and virtual gateway sniffing.  
> The tool degrades gracefully when run without root (uses `arp -a` cache and `ping` instead).

---

##  Usage

### Full Scan (recommended)
```bash
sudo gf scan
```
Auto-detects interface, network, and default gateway. Runs discovery →
fingerprinting → security scan → scoring.

```bash
sudo gf scan -n 192.168.1.0/24 -I eth0 -t 8.8.8.8
```

### All options for `scan`
```
Options:
  -I, --interface IFACE   Network interface (auto-detect if omitted)
  -n, --network   CIDR    ARP-scan target (e.g. 192.168.1.0/24)
  -t, --target    IP      Internet IP for routing probes [default: 8.8.8.8]
  -f, --mac-file  FILE    Load MAC candidates from file
  -T, --timeout   SEC     Per-probe timeout [default: 3]
      --no-finger         Skip fingerprinting
      --no-scan           Skip security port scan
      --no-score          Skip scoring engine
      --no-virtual        Skip HSRP/VRRP/GLBP sniffing
  -o, --output    FILE    Save results to file
  -F, --format    FMT     json | csv | html | all
  -v, --verbose           Show recommendations + debug info
```

### Probe Mode (original `gateway-finder` functionality, enhanced)
```bash
sudo gf probe -t 8.8.8.8 -f macs.txt -I eth0
```
Tests routing capability of each MAC in `macs.txt` by sending ICMP and
TCP/80 probes with TTL=1.

`macs.txt` supports multiple formats:
```
# Plain MAC
00:11:22:33:44:55

# IP + MAC (space or tab separated)
192.168.1.1  00:11:22:33:44:55

# MAC + IP (any order)
00-AA-BB-CC-DD-EE   10.0.0.1 (gateway)
```

### Monitor a Gateway
```bash
gf monitor -t 192.168.1.1 --interval 2
gf monitor -t 10.0.0.1 --interval 5 --duration 3600 -o events.json
```

```
Options:
  -t, --target    IP      Gateway IP to monitor (required)
  -i, --interval  FLOAT   Ping interval in seconds [default: 5.0]
  -d, --duration  INT     Stop after N seconds (0 = until Ctrl-C)
  -o, --output    FILE    Save event log to JSON on exit
```

### Re-generate Reports
```bash
gf report scan_results.json -F html -o report.html
gf report scan_results.json -F all
```

### List Interfaces
```bash
gf ifaces
```

### Export Formats
```bash
# Single format
sudo gf scan -o results.json
sudo gf scan -o results.html
sudo gf scan -o results.csv

# All formats at once
sudo gf scan -F all
```

---

##  Example Output

```
 ██████╗  █████╗ ████████╗███████╗██╗    ██╗ █████╗ ██╗   ██╗
...
  GatewayFinder v2.0.0  |  Authorized Use Only

══════════════════════ Gateway Intelligence Report ══════════════════════

╭─ DEFAULT ─ 192.168.1.1  HIGH ────────────────────────────────────────╮
│  MAC:         00:00:0C:AA:BB:CC                                       │
│  Vendor:      Cisco                                                    │
│  Hostname:    router.local                                             │
│  OS Guess:    Cisco IOS / Juniper JunOS / Network OS                  │
│  Interface:   eth0                                                     │
│  Method:      routing_table/proc_net_route  (high)                    │
│  Routing:     ICMP + TCP                                               │
│  RTT:         1.43 ms                                                  │
│                                                                        │
│  Security:    65/100   Exposure: 55/100   Availability: 90/100        │
│                                                                        │
│  Open Ports:  22/SSH  23/Telnet  80/HTTP  161/SNMP  443/HTTPS         │
│                                                                        │
│  Vulnerabilities:                                                      │
│   ⚠ Telnet enabled — unencrypted remote access (port 23)              │
│   ⚠ SNMP default community 'public' accepted                          │
╰────────────────────────────────────────────────────────────────────────╯

┌──────────────┬────────┬──────────┬───────┬─────┬─────┬──────┬───────┐
│ IP           │ Vendor │ Routing  │ Ports │ Sec │ Exp │ Risk │ Vulns │
├──────────────┼────────┼──────────┼───────┼─────┼─────┼──────┼───────┤
│ 192.168.1.1  │ Cisco  │ ICMP+TCP │ 5     │ 65  │ 55  │ HIGH │ 2     │
└──────────────┴────────┴──────────┴───────┴─────┴─────┴──────┴───────┘
```

---

##  Project Structure

```
gateway-finder/
├── gateway_finder/
│   ├── __init__.py
│   ├── cli.py                  # Click CLI — entry point (gf command)
│   ├── core/
│   │   ├── discovery.py        # ARP scan, routing probes, HSRP/VRRP/GLBP
│   │   ├── fingerprint.py      # OUI, TTL, HTTP, SSL fingerprinting
│   │   ├── scanner.py          # Port scan, SNMP, Telnet, TLS checks
│   │   ├── monitor.py          # Real-time ICMP monitoring
│   │   └── scoring.py          # Security/Exposure/Availability scoring
│   ├── utils/
│   │   └── helpers.py          # Network utilities, cross-platform helpers
│   └── reports/
│       └── reporter.py         # JSON / CSV / HTML export
├── tests/
│   └── test_discovery.py       # 35+ unit tests (no network required)
├── Dockerfile
├── requirements.txt
├── setup.py
└── README.md
```

---

##  Dependency Matrix

| Feature | Requires | Fallback |
|---------|----------|----------|
| ARP scan | scapy + root | `arp -a` cache |
| Routing probes | scapy + root | `ping` |
| Virtual GW (HSRP/VRRP) | scapy + root | — |
| SNMP v1/v2c probe | scapy (optional) | raw UDP socket |
| Port scan | socket (stdlib) | — |
| Interface detection | netifaces | `ip addr` / `netstat` |
| TTL fingerprinting | scapy or `ping` | — |

**Minimum setup** (no root, no scapy):
```bash
pip install click rich netifaces
gf scan    # uses arp cache + ping fallbacks
```

**Full setup** (root + scapy):
```bash
pip install -r requirements.txt
sudo gf scan
```

---

##  Testing

```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run all tests (no network, no root needed)
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=gateway_finder --cov-report=term-missing
```

---

##  Integrations

### Nmap
```bash
# Pipe discovered IPs into nmap for deep service scan
sudo gf scan -F json -o scan.json
jq -r '.gateways[].ip' scan.json | xargs nmap -sV -O -p-
```

### Elasticsearch / Splunk
```bash
# JSON output is SIEM-ready
sudo gf scan -F json -o - | curl -X POST http://elastic:9200/gateways/_doc -d @-
```

### Cronjob monitoring with alerting
```bash
# Monitor every 10 minutes, save events
*/10 * * * * gf monitor -t 192.168.1.1 -d 600 -o /var/log/gf_events.json
```

---

## Roadmap

- [ ] Nmap integration (`--nmap` flag)
- [ ] REST API (`gf serve --port 8080`)
- [ ] SNMP v3 support
- [ ] IPv6 full routing probes
- [ ] BGP route change tracking
- [ ] Webhook alerts (`--webhook URL`)
- [ ] React dashboard frontend
- [ ] Local LLM analysis backend

---

##  License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**KiranKurbet** — Red Teamer @ Cyart Technology  
Certifications: CPENT · CEH · CASA · APIsec Practitioner · API Security Fundamentals  
GitHub: [@KiranKurbet](https://github.com/KiranKurbet)

---

*Evolved from the original [gateway-finder](http://pentestmonkey.net/tools/gateway-finder) by pentestmonkey.*
