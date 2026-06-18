"""
GatewayFinder CLI — Professional Network Gateway Intelligence Tool
Usage: gf [command] [options]
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import List, Optional

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import print as rprint

from gateway_finder.core.discovery import DiscoveryEngine, GatewayInfo
from gateway_finder.core.fingerprint import FingerprintEngine
from gateway_finder.core.scanner import SecurityScanner
from gateway_finder.core.scoring import ScoringEngine
from gateway_finder.core.monitor import GatewayMonitor
from gateway_finder.reports.reporter import Reporter
from gateway_finder.utils.helpers import (
    get_local_interfaces, is_root, pick_best_interface, ping_host,
)

console = Console(stderr=False)

VERSION = "2.0.0"

BANNER = r"""
 ██████╗  █████╗ ████████╗███████╗██╗    ██╗ █████╗ ██╗   ██╗
██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║    ██║██╔══██╗╚██╗ ██╔╝
██║  ███╗███████║   ██║   █████╗  ██║ █╗ ██║███████║ ╚████╔╝
██║   ██║██╔══██║   ██║   ██╔══╝  ██║███╗██║██╔══██║  ╚██╔╝
╚██████╔╝██║  ██║   ██║   ███████╗╚███╔███╔╝██║  ██║   ██║
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝
          ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
          ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
          █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
          ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
          ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
          ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"""

RISK_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "Unknown":  "dim",
}

CONF_STYLE = {
    "confirmed": "bold green",
    "high":      "green",
    "medium":    "yellow",
    "low":       "dim",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Root CLI group
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(VERSION, "-V", "--version")
@click.option("--verbose", "-v", is_flag=True, help="Debug-level logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """
    \b
    GatewayFinder v{version} — Gateway Intelligence Engine
    Authorized penetration testing and network assessment only.
    """.format(version=VERSION)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="[%(levelname)s] %(name)s: %(message)s",
        level=level,
        stream=sys.stderr,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# scan
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("scan")
@click.option("--interface", "-I", default=None, metavar="IFACE",
              help="Network interface (auto-detect if omitted).")
@click.option("--network",   "-n", default=None, metavar="CIDR",
              help="Target CIDR to ARP-scan (e.g. 192.168.1.0/24).")
@click.option("--target",    "-t", default="8.8.8.8", metavar="IP",
              show_default=True, help="Internet IP used for routing probes.")
@click.option("--mac-file",  "-f", default=None, metavar="FILE",
              help="Load MAC candidates from file.")
@click.option("--timeout",   "-T", default=3, type=int, metavar="SEC",
              show_default=True, help="Per-probe timeout.")
@click.option("--no-finger", is_flag=True, help="Skip fingerprinting.")
@click.option("--no-scan",   is_flag=True, help="Skip security port scan.")
@click.option("--no-score",  is_flag=True, help="Skip scoring.")
@click.option("--no-virtual",is_flag=True, help="Skip virtual GW sniffing.")
@click.option("--output",    "-o", default=None, metavar="FILE",
              help="Save results to file (auto-detect format from extension).")
@click.option("--format",    "-F", "fmt",
              type=click.Choice(["json","csv","html","all"]), default=None,
              help="Force output format (overrides --output extension).")
@click.pass_context
def cmd_scan(
    ctx,
    interface, network, target, mac_file,
    timeout, no_finger, no_scan, no_score, no_virtual,
    output, fmt,
):
    """Full gateway discovery + fingerprinting + security scan."""
    _print_banner()

    if not is_root():
        console.print(
            "[yellow]⚠  Not running as root — ARP scan, routing probes, and "
            "virtual GW detection require root/sudo.[/yellow]\n"
        )

    iface = interface or pick_best_interface()

    steps = []
    steps.append("Discovery")
    if not no_finger: steps.append("Fingerprinting")
    if not no_scan:   steps.append("Security Scan")
    if not no_score:  steps.append("Scoring")

    gateways: List[GatewayInfo] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        # ── Step 1: Discovery ────────────────────────────────────────────────
        task = prog.add_task("Discovering gateways…", total=None)
        msgs = []

        def _update(msg: str) -> None:
            msgs.append(msg)
            prog.update(task, description=msg)

        engine = DiscoveryEngine(
            interface   = iface,
            timeout     = timeout,
            progress_cb = _update,
        )
        gateways = engine.run(
            target_ip      = target,
            network        = network,
            mac_file       = mac_file,
            probe_routing  = True,
            detect_virtual = not no_virtual,
        )
        prog.update(task, description=f"Discovery complete — {len(gateways)} found")

        if not gateways:
            console.print("\n[red]No gateways found. Try running as root or specify --network.[/red]")
            sys.exit(1)

        # ── Step 2: Fingerprinting ───────────────────────────────────────────
        if not no_finger:
            fp_engine = FingerprintEngine(timeout=timeout)
            fp_task   = prog.add_task("Fingerprinting…", total=len(gateways))
            for gw in gateways:
                prog.update(fp_task, description=f"Fingerprinting {gw.ip}…")
                fp_engine.run(gw)
                prog.advance(fp_task)
            prog.update(fp_task, description="Fingerprinting complete")

        # ── Step 3: Security scan ────────────────────────────────────────────
        if not no_scan:
            scanner  = SecurityScanner(timeout=timeout)
            sc_task  = prog.add_task("Security scan…", total=len(gateways))
            for gw in gateways:
                prog.update(sc_task, description=f"Scanning {gw.ip}…")
                scanner.run(gw)
                prog.advance(sc_task)
            prog.update(sc_task, description="Security scan complete")

        # ── Step 4: Scoring ──────────────────────────────────────────────────
        if not no_score:
            scorer = ScoringEngine()
            for gw in gateways:
                scorer.run(gw)

    # ── Print results ────────────────────────────────────────────────────────
    _print_results(gateways, verbose=ctx.obj.get("verbose", False))

    # ── Export ───────────────────────────────────────────────────────────────
    if output or fmt:
        _export(gateways, output=output, fmt=fmt)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# probe  (enhanced version of the original script)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("probe")
@click.option("--target",    "-t", required=True, metavar="IP",
              help="Internet IP to probe through candidate gateways.")
@click.option("--mac-file",  "-f", required=True, metavar="FILE",
              help="File containing MAC addresses to probe.")
@click.option("--interface", "-I", default=None, metavar="IFACE",
              help="Network interface.")
@click.option("--timeout",   "-T", default=3, type=int, show_default=True)
@click.pass_context
def cmd_probe(ctx, target, mac_file, interface, timeout):
    """
    Probe routing capability of specific MACs (original gateway-finder mode).
    Sends ICMP and TCP/80 with TTL=1 through each MAC and listens for replies.
    Requires root and scapy.
    """
    _print_banner()

    if not is_root():
        console.print("[red]Error: probe command requires root/sudo privileges.[/red]")
        sys.exit(1)

    try:
        from scapy.all import conf as scapy_conf
    except ImportError:
        console.print("[red]Error: probe command requires scapy. Run: pip install scapy[/red]")
        sys.exit(1)

    iface = interface or pick_best_interface()

    engine = DiscoveryEngine(interface=iface, timeout=timeout)
    candidates = engine.from_file(mac_file)

    if not candidates:
        console.print(f"[red]No valid MAC addresses found in {mac_file}[/red]")
        sys.exit(1)

    console.print(f"\n[cyan]Loaded [bold]{len(candidates)}[/bold] MAC addresses from [bold]{mac_file}[/bold][/cyan]")
    console.print(f"[cyan]Probing via interface [bold]{iface}[/bold] → target [bold]{target}[/bold]\n[/cyan]")

    engine.probe_routing(candidates, target_ip=target)

    table = Table(title="Routing Probe Results", box=box.ROUNDED, style="cyan")
    table.add_column("MAC",        style="white",       no_wrap=True)
    table.add_column("IP",         style="cyan")
    table.add_column("Routes ICMP",justify="center")
    table.add_column("Routes TCP", justify="center")
    table.add_column("TTL Exc.",   justify="center")

    found = 0
    for gw in candidates:
        if gw.routes_icmp or gw.routes_tcp:
            found += 1
        table.add_row(
            gw.mac,
            gw.ip or "—",
            "✓" if gw.routes_icmp else "✗",
            "✓" if gw.routes_tcp  else "✗",
            "✓" if gw.ttl_exceeded else "—",
            style="bold green" if (gw.routes_icmp or gw.routes_tcp) else "dim",
        )

    console.print(table)
    console.print(f"\n[bold]{'[green]' if found else '[red]'}{found} gateway(s) confirmed routing to {target}[/bold]")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# monitor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("monitor")
@click.option("--target",   "-t", required=True, metavar="IP",
              help="Gateway IP to monitor.")
@click.option("--interval", "-i", default=5.0, type=float, show_default=True,
              help="Ping interval in seconds.")
@click.option("--duration", "-d", default=0, type=int,
              help="Stop after N seconds (0 = run until Ctrl-C).")
@click.option("--output",   "-o", default=None, metavar="FILE",
              help="Save event log to JSON file on exit.")
def cmd_monitor(target: str, interval: float, duration: int, output: Optional[str]):
    """Real-time gateway uptime and latency monitoring."""
    _print_banner()

    console.print(
        Panel.fit(
            f"[cyan]Monitoring [bold]{target}[/bold] every [bold]{interval}s[/bold]\n"
            "[dim]Press Ctrl-C to stop.[/dim]",
            title="GatewayFinder Monitor",
            border_style="cyan",
        )
    )

    mon = GatewayMonitor(target=target, interval=interval)

    def _alert(etype: str, msg: str) -> None:
        style = "bold red" if "DOWN" in etype else (
                "bold green" if "UP" in etype else "yellow")
        console.print(f"  [{style}][{etype}][/{style}] {msg}")

    mon.on_alert(_alert)
    mon.start()

    start = time.monotonic()
    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                time.sleep(1)
                stats = mon.get_stats()
                live.update(_monitor_table(stats))

                if duration and (time.monotonic() - start) >= duration:
                    break

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/yellow]")
    finally:
        mon.stop()
        stats = mon.get_stats()
        console.print("\n")
        console.print(_monitor_summary(stats))

        if output:
            import json
            from dataclasses import asdict
            data = {
                "target":   target,
                "stats":    {
                    "uptime_pct":    stats.uptime_pct,
                    "loss_pct":      stats.loss_pct,
                    "avg_ms":        stats.avg_ms,
                    "min_ms":        stats.min_ms,
                    "max_ms":        stats.max_ms,
                    "jitter_ms":     stats.jitter_ms,
                    "total_sent":    stats.total_sent,
                    "total_received":stats.total_received,
                },
                "events": stats.events,
            }
            with open(output, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"[green]Event log saved to {output}[/green]")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# report  (re-process saved JSON)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("report")
@click.argument("input_json", metavar="INPUT.json")
@click.option("--format", "-F", "fmt",
              type=click.Choice(["html","csv","json","all"]),
              default="html", show_default=True)
@click.option("--output", "-o", default=None, metavar="FILE")
def cmd_report(input_json: str, fmt: str, output: Optional[str]):
    """Re-generate a report from a previously saved JSON scan file."""
    try:
        with open(input_json) as f:
            raw = json.load(f)
    except Exception as e:
        console.print(f"[red]Cannot open {input_json}: {e}[/red]")
        sys.exit(1)

    gateways = []
    for d in raw.get("gateways", []):
        gw = GatewayInfo()
        for k, v in d.items():
            if hasattr(gw, k):
                setattr(gw, k, v)
        gateways.append(gw)

    _export(gateways, output=output, fmt=fmt)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ifaces  (helper — list interfaces)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@cli.command("ifaces")
def cmd_ifaces():
    """List available network interfaces."""
    ifaces = get_local_interfaces()
    if not ifaces:
        console.print("[red]No active interfaces found.[/red]")
        return

    table = Table(title="Network Interfaces", box=box.ROUNDED)
    table.add_column("Name",  style="bold cyan", no_wrap=True)
    table.add_column("IPv4",  style="white")
    table.add_column("Mask",  style="dim")
    table.add_column("MAC",   style="yellow")
    table.add_column("IPv6",  style="dim", overflow="fold")

    for i in ifaces:
        table.add_row(
            i["name"],
            i["ipv4"],
            i["ipv4_mask"],
            i["mac"],
            ", ".join(i["ipv6"])[:50] if i["ipv6"] else "—",
        )
    console.print(table)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Display helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _print_banner() -> None:
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        f"[dim]  GatewayFinder v{VERSION}  |  Authorized Use Only  |  "
        "github.com/KiranKurbet/GatewayFinder[/dim]\n"
    )


def _print_results(gateways: List[GatewayInfo], verbose: bool = False) -> None:
    console.rule("[bold cyan]Gateway Intelligence Report[/bold cyan]")
    console.print()

    for gw in gateways:
        _print_gateway_panel(gw, verbose=verbose)

    # Summary table
    table = Table(
        title="Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
    )
    table.add_column("IP",         style="bold white", no_wrap=True)
    table.add_column("Vendor",     style="cyan")
    table.add_column("Routing",    justify="center")
    table.add_column("Ports",      justify="right")
    table.add_column("Sec",        justify="right")
    table.add_column("Exp",        justify="right")
    table.add_column("Risk",       justify="center")
    table.add_column("Vulns",      justify="right")

    for gw in gateways:
        risk_style = RISK_STYLE.get(gw.risk_level, "")
        routing_str = (
            "[green]ICMP+TCP[/green]"  if gw.routes_icmp and gw.routes_tcp else
            "[green]ICMP[/green]"       if gw.routes_icmp else
            "[green]TCP[/green]"        if gw.routes_tcp  else
            "[dim]None[/dim]"
        )
        flags = ""
        if gw.is_default: flags += "[cyan][D][/cyan]"
        if gw.is_virtual: flags += f"[yellow][{gw.virtual_protocol}][/yellow]"

        table.add_row(
            f"{gw.ip} {flags}",
            gw.vendor[:22] if gw.vendor != "Unknown" else "[dim]Unknown[/dim]",
            routing_str,
            str(len(gw.open_ports)),
            (f"[{'green' if gw.security_score >= 80 else 'yellow' if gw.security_score >= 60 else 'red'}]"
             f"{gw.security_score}[/]") if gw.security_score >= 0 else "—",
            str(gw.exposure_score) if gw.exposure_score >= 0 else "—",
            f"[{risk_style}]{gw.risk_level}[/{risk_style}]",
            (f"[red]{len(gw.vulnerabilities)}[/red]"
             if gw.vulnerabilities else "[green]0[/green]"),
        )

    console.print(table)
    console.print()


def _print_gateway_panel(gw: GatewayInfo, verbose: bool) -> None:
    risk_style = RISK_STYLE.get(gw.risk_level, "")
    flags      = []
    if gw.is_default: flags.append("[cyan bold]DEFAULT[/cyan bold]")
    if gw.is_virtual: flags.append(f"[yellow bold]{gw.virtual_protocol}[/yellow bold]")
    flag_str   = "  ".join(flags) + "  " if flags else ""

    title = f"{flag_str}[bold white]{gw.ip}[/bold white]  [{risk_style}]{gw.risk_level}[/{risk_style}]"

    lines: List[str] = []

    # Identity
    lines += [
        f"  [bold]MAC:[/bold]         {gw.mac or '—'}",
        f"  [bold]Vendor:[/bold]      {gw.vendor}",
        f"  [bold]Hostname:[/bold]    {gw.hostname or '—'}",
        f"  [bold]OS Guess:[/bold]    {gw.os_guess}",
        f"  [bold]Interface:[/bold]   {gw.interface}",
        f"  [bold]Method:[/bold]      {gw.discovery_method}  "
            f"[{CONF_STYLE.get(gw.confidence,'dim')}]({gw.confidence})[/{CONF_STYLE.get(gw.confidence,'dim')}]",
    ]
    if gw.router_model:
        lines.append(f"  [bold]Model:[/bold]       {gw.router_model[:80]}")
    if gw.management_url:
        lines.append(f"  [bold]Mgmt URL:[/bold]    [link={gw.management_url}]{gw.management_url}[/link]")
    if gw.cloud_provider:
        lines.append(f"  [bold]Cloud:[/bold]       [cyan]{gw.cloud_provider}[/cyan]")

    # Routing
    routing = (
        "[green]ICMP + TCP[/green]"  if gw.routes_icmp and gw.routes_tcp else
        "[green]ICMP[/green]"         if gw.routes_icmp else
        "[green]TCP[/green]"          if gw.routes_tcp  else
        "[dim]Not confirmed[/dim]"
    )
    lines.append(f"  [bold]Routing:[/bold]     {routing}")
    if gw.response_time_ms:
        lines.append(f"  [bold]RTT:[/bold]         {gw.response_time_ms:.2f} ms")

    # Scores
    if gw.security_score >= 0:
        sc = gw.security_score
        sc_color = "green" if sc >= 80 else "yellow" if sc >= 60 else "red"
        lines += [
            "",
            f"  [bold]Security:[/bold]    [{sc_color}]{sc}/100[/{sc_color}]"
                f"  Exposure: {gw.exposure_score}/100"
                f"  Availability: {gw.availability_score}/100",
        ]

    # Open ports
    if gw.open_ports:
        port_parts = []
        for p in gw.open_ports:
            svc = gw.services.get(p, "")
            danger = p in (23, 161, 8291, 8728, 623)
            col = "red" if danger else "white"
            port_parts.append(f"[{col}]{p}[/{col}][dim]/{svc}[/dim]")
        lines.append(f"\n  [bold]Open Ports:[/bold]  {' '.join(port_parts)}")

    # Vulnerabilities
    if gw.vulnerabilities:
        lines.append("\n  [bold red]Vulnerabilities:[/bold red]")
        for v in gw.vulnerabilities:
            lines.append(f"    [red]⚠[/red] {v}")

    # Recommendations
    if gw.recommendations and verbose:
        lines.append("\n  [bold cyan]Recommendations:[/bold cyan]")
        for r in gw.recommendations:
            lines.append(f"    [cyan]→[/cyan] {r}")

    content = "\n".join(lines)
    border = "red" if gw.risk_level == "CRITICAL" else (
             "yellow" if gw.risk_level == "HIGH" else (
             "yellow" if gw.risk_level == "MEDIUM" else "green"))

    console.print(Panel(content, title=title, border_style=border, expand=False))
    console.print()


def _monitor_table(stats) -> Table:
    t = Table(box=box.ROUNDED, title=f"Monitoring {stats.target}", expand=False)
    t.add_column("Metric", style="cyan bold", width=20)
    t.add_column("Value",  style="white",     width=20)

    up_str = "[bold green]UP[/bold green]" if stats.is_up else "[bold red]DOWN[/bold red]"
    t.add_row("Status",    up_str)
    t.add_row("Uptime",    f"{stats.uptime_pct:.1f}%")
    t.add_row("Loss",      f"[red]{stats.loss_pct:.1f}%[/red]" if stats.loss_pct > 5 else f"{stats.loss_pct:.1f}%")
    t.add_row("Avg RTT",   f"{stats.avg_ms:.2f} ms" if stats.avg_ms else "—")
    t.add_row("Min/Max",   f"{stats.min_ms:.1f} / {stats.max_ms:.1f} ms" if stats.max_ms else "—")
    t.add_row("Jitter",    f"{stats.jitter_ms:.2f} ms" if stats.jitter_ms else "—")
    t.add_row("Sent/Rcvd", f"{stats.total_sent} / {stats.total_received}")
    return t


def _monitor_summary(stats) -> Panel:
    lines = [
        f"  Target:        [bold]{stats.target}[/bold]",
        f"  Final Status:  {'[bold green]UP[/bold green]' if stats.is_up else '[bold red]DOWN[/bold red]'}",
        f"  Uptime:        {stats.uptime_pct:.1f}%",
        f"  Packet Loss:   {stats.loss_pct:.1f}%",
        f"  Avg/Min/Max:   {stats.avg_ms:.1f} / {stats.min_ms:.1f} / {stats.max_ms:.1f} ms",
        f"  Jitter:        {stats.jitter_ms:.2f} ms",
        f"  Probes:        {stats.total_sent} sent, {stats.total_received} received",
    ]
    if stats.events:
        lines.append("\n  [bold]Events:[/bold]")
        for e in stats.events[-10:]:
            lines.append(f"    {e}")
    return Panel("\n".join(lines), title="Monitor Summary", border_style="cyan")


def _export(gateways: List[GatewayInfo], output: Optional[str], fmt: Optional[str]) -> None:
    rep = Reporter(gateways)
    exported = []

    # Determine format from output file extension if fmt not set
    if not fmt and output:
        ext = os.path.splitext(output)[1].lstrip(".")
        if ext in ("json", "csv", "html"):
            fmt = ext

    fmt = fmt or "json"

    if fmt in ("json", "all"):
        p = rep.save_json(output if fmt == "json" else None)
        exported.append(p)
    if fmt in ("html", "all"):
        p = rep.save_html(output if fmt == "html" else None)
        exported.append(p)
    if fmt in ("csv", "all"):
        p = rep.save_csv(output if fmt == "csv" else None)
        exported.append(p)

    for p in exported:
        console.print(f"[green]✓ Report saved:[/green] {p}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
