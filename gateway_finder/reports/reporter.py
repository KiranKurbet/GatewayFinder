"""
Gateway Finder - Report Generator
Exports scan results to JSON, CSV, and a self-contained HTML report.
"""

from __future__ import annotations

import csv
import json
import os
import time
from pathlib import Path
from typing import List, Optional

from gateway_finder.core.discovery import GatewayInfo

_RISK_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2ecc71",
    "Unknown":  "#95a5a6",
}

_RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "Unknown":  "⚪",
}


class Reporter:
    """Generate reports from a list of GatewayInfo objects."""

    def __init__(self, gateways: List[GatewayInfo], scan_meta: Optional[dict] = None):
        self.gateways  = gateways
        self.meta      = scan_meta or {}
        self._ts       = time.strftime("%Y-%m-%d %H:%M:%S")
        self._ts_file  = time.strftime("%Y%m%d_%H%M%S")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # JSON
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def save_json(self, path: Optional[str] = None) -> str:
        path = path or f"gf_report_{self._ts_file}.json"
        data = {
            "meta": {
                "tool":      "GatewayFinder",
                "version":   "2.0",
                "generated": self._ts,
                **self.meta,
            },
            "summary": self._summary(),
            "gateways": [gw.to_dict() for gw in self.gateways],
        }
        Path(path).write_text(json.dumps(data, indent=2))
        return path

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CSV
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def save_csv(self, path: Optional[str] = None) -> str:
        path = path or f"gf_report_{self._ts_file}.csv"
        fields = [
            "ip", "mac", "hostname", "interface", "vendor", "os_guess",
            "is_default", "is_virtual", "virtual_protocol",
            "routes_icmp", "routes_tcp", "open_ports", "has_telnet",
            "has_snmp", "snmp_community", "weak_tls", "self_signed_cert",
            "security_score", "exposure_score", "availability_score",
            "risk_level", "management_url", "cloud_provider",
            "discovery_method", "confidence",
        ]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for gw in self.gateways:
                row = gw.to_dict()
                row["open_ports"] = "|".join(str(p) for p in row.get("open_ports", []))
                w.writerow(row)
        return path

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # HTML
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def save_html(self, path: Optional[str] = None) -> str:
        path = path or f"gf_report_{self._ts_file}.html"
        Path(path).write_text(self._build_html())
        return path

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Internal helpers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _summary(self) -> dict:
        total = len(self.gateways)
        routing = sum(1 for g in self.gateways if g.routes_icmp or g.routes_tcp)
        vuln    = sum(1 for g in self.gateways if g.vulnerabilities)
        critical = sum(1 for g in self.gateways if g.risk_level == "CRITICAL")
        high     = sum(1 for g in self.gateways if g.risk_level == "HIGH")
        return {
            "total_gateways": total,
            "routing_confirmed": routing,
            "with_vulnerabilities": vuln,
            "critical_risk": critical,
            "high_risk": high,
        }

    def _build_html(self) -> str:
        summary = self._summary()
        gw_cards = "\n".join(self._gw_card(gw) for gw in self.gateways)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>GatewayFinder Report — {self._ts}</title>
<style>
  :root{{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#c9d1d9;
         --accent:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
        font-size:14px;padding:20px;}}
  h1{{font-size:1.8rem;color:var(--accent);margin-bottom:4px;}}
  .subtitle{{color:#8b949e;margin-bottom:24px;}}
  .summary{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px;}}
  .stat{{background:var(--panel);border:1px solid var(--border);border-radius:8px;
          padding:16px 24px;min-width:140px;text-align:center;}}
  .stat .num{{font-size:2rem;font-weight:700;color:var(--accent);}}
  .stat .lbl{{font-size:0.75rem;color:#8b949e;margin-top:4px;}}
  .card{{background:var(--panel);border:1px solid var(--border);border-radius:10px;
          margin-bottom:18px;overflow:hidden;}}
  .card-header{{display:flex;align-items:center;gap:14px;padding:14px 18px;
                 border-bottom:1px solid var(--border);}}
  .ip{{font-size:1.2rem;font-weight:700;color:var(--accent);}}
  .badge{{border-radius:4px;padding:3px 9px;font-size:0.72rem;font-weight:600;}}
  .badge-default{{background:#1f6feb22;color:#58a6ff;border:1px solid #1f6feb;}}
  .badge-virtual{{background:#6e4000;color:#e3b341;border:1px solid #d29922;}}
  .risk{{border-radius:4px;padding:3px 9px;font-size:0.8rem;font-weight:700;margin-left:auto;}}
  .card-body{{display:grid;grid-template-columns:1fr 1fr;gap:0;}}
  .section{{padding:14px 18px;border-right:1px solid var(--border);}}
  .section:last-child{{border-right:none;}}
  .section h3{{font-size:0.7rem;text-transform:uppercase;color:#8b949e;
                letter-spacing:.08em;margin-bottom:8px;}}
  .kv{{display:flex;justify-content:space-between;padding:3px 0;
        border-bottom:1px solid #21262d;font-size:0.82rem;}}
  .kv:last-child{{border-bottom:none;}}
  .kv .k{{color:#8b949e;}}
  .kv .v{{color:var(--text);font-weight:500;max-width:60%;text-align:right;word-break:break-all;}}
  .score-bar{{height:8px;border-radius:4px;background:#21262d;margin-top:4px;}}
  .score-fill{{height:100%;border-radius:4px;transition:width .3s;}}
  .ports{{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px;}}
  .port{{background:#21262d;border-radius:4px;padding:2px 7px;font-size:0.75rem;
          font-family:monospace;}}
  .port.danger{{background:#3d1a1a;color:#f85149;}}
  .port.warn{{background:#3d2b00;color:#e3b341;}}
  .vuln-list{{margin-top:6px;}}
  .vuln{{background:#1a1a2e;border-left:3px solid var(--red);padding:6px 10px;
          margin-bottom:5px;font-size:0.78rem;border-radius:0 4px 4px 0;}}
  .rec{{background:#0a1628;border-left:3px solid var(--accent);padding:6px 10px;
         margin-bottom:5px;font-size:0.78rem;border-radius:0 4px 4px 0;}}
  .ok{{color:var(--green);}} .bad{{color:var(--red);}} .warn-txt{{color:#e3b341;}}
  footer{{text-align:center;color:#8b949e;margin-top:32px;font-size:0.75rem;}}
  @media(max-width:600px){{.card-body{{grid-template-columns:1fr;}}
    .section{{border-right:none;border-bottom:1px solid var(--border);}}}}
</style>
</head>
<body>
<h1>🛡️ GatewayFinder Intelligence Report</h1>
<p class="subtitle">Generated: {self._ts} &nbsp;|&nbsp; Tool: GatewayFinder v2.0</p>

<div class="summary">
  <div class="stat"><div class="num">{summary["total_gateways"]}</div><div class="lbl">Gateways Found</div></div>
  <div class="stat"><div class="num">{summary["routing_confirmed"]}</div><div class="lbl">Routing Confirmed</div></div>
  <div class="stat"><div class="num" style="color:#f85149">{summary["critical_risk"]}</div><div class="lbl">Critical Risk</div></div>
  <div class="stat"><div class="num" style="color:#d29922">{summary["high_risk"]}</div><div class="lbl">High Risk</div></div>
  <div class="stat"><div class="num" style="color:#f85149">{summary["with_vulnerabilities"]}</div><div class="lbl">With Vulns</div></div>
</div>

{gw_cards}

<footer>GatewayFinder v2.0 — Authorized Use Only — {self._ts}</footer>
</body></html>"""

    def _gw_card(self, gw: GatewayInfo) -> str:
        risk_color = _RISK_COLORS.get(gw.risk_level, "#95a5a6")
        risk_emoji = _RISK_EMOJI.get(gw.risk_level, "⚪")
        sec_color  = ("#2ecc71" if gw.security_score >= 80 else
                      "#f1c40f" if gw.security_score >= 60 else
                      "#e67e22" if gw.security_score >= 40 else "#e74c3c")
        badges = ""
        if gw.is_default:
            badges += '<span class="badge badge-default">DEFAULT GW</span>'
        if gw.is_virtual:
            badges += f'<span class="badge badge-virtual">{gw.virtual_protocol}</span>'

        ports_html = ""
        for port in gw.open_ports:
            cls = "danger" if port in (23, 161) else "warn" if port in (8291, 8728, 623) else ""
            svc = gw.services.get(port, "")
            ports_html += f'<span class="port {cls}">{port}/{svc}</span>'

        vulns_html = "".join(
            f'<div class="vuln">⚠ {v}</div>' for v in gw.vulnerabilities
        ) or '<span style="color:#3fb950;font-size:.8rem">✓ No confirmed vulnerabilities</span>'

        recs_html = "".join(
            f'<div class="rec">→ {r}</div>' for r in gw.recommendations
        ) or ""

        def kv(k, v, cls=""):
            c = f' class="{cls}"' if cls else ""
            return f'<div class="kv"><span class="k">{k}</span><span class="v"{c}>{v}</span></div>'

        def yes_no(val: bool) -> str:
            return '<span class="ok">Yes</span>' if val else '<span class="bad">No</span>'

        def score_bar(score: int, color: str) -> str:
            if score < 0:
                return ""
            return (
                f'<div class="score-bar"><div class="score-fill" '
                f'style="width:{score}%;background:{color}"></div></div>'
            )

        routing = (
            f'{"<span class=ok>ICMP</span>" if gw.routes_icmp else ""} '
            f'{"<span class=ok>TCP</span>"  if gw.routes_tcp  else ""}'
        ).strip() or '<span class="bad">Unconfirmed</span>'

        return f"""
<div class="card">
  <div class="card-header">
    <div class="ip">{gw.ip}</div>
    {badges}
    <div class="risk" style="background:{risk_color}22;color:{risk_color};border:1px solid {risk_color}">
      {risk_emoji} {gw.risk_level}
    </div>
  </div>
  <div class="card-body">
    <div class="section">
      <h3>Identity</h3>
      {kv("MAC",       gw.mac        or "Unknown")}
      {kv("Vendor",    gw.vendor     or "Unknown")}
      {kv("Hostname",  gw.hostname   or "—")}
      {kv("OS Guess",  gw.os_guess   or "Unknown")}
      {kv("Model",     gw.router_model or "—")}
      {kv("Interface", gw.interface  or "—")}
      {kv("Method",    gw.discovery_method)}
      {kv("Routing",   routing)}
      {kv("Cloud",     gw.cloud_provider or "—")}
    </div>
    <div class="section">
      <h3>Scores</h3>
      {kv("Security",    f"{gw.security_score}/100" if gw.security_score >= 0 else "—")}
      {score_bar(gw.security_score, sec_color)}
      {kv("Exposure",    f"{gw.exposure_score}/100"    if gw.exposure_score >= 0 else "—")}
      {score_bar(gw.exposure_score, "#e74c3c")}
      {kv("Availability",f"{gw.availability_score}/100" if gw.availability_score >= 0 else "—")}
      {score_bar(gw.availability_score, "#2ecc71")}
      <br/>
      <h3>Services ({len(gw.open_ports)} open)</h3>
      <div class="ports">{ports_html or "None found"}</div>
    </div>
    <div class="section">
      <h3>Vulnerabilities</h3>
      {vulns_html}
    </div>
    <div class="section">
      <h3>Recommendations</h3>
      {recs_html or '<span style="color:#3fb950;font-size:.8rem">✓ No actions required</span>'}
    </div>
  </div>
</div>"""
