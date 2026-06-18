"""
Gateway Finder - Real-Time Monitor
Continuously pings a gateway and tracks latency, packet loss,
route changes, and state transitions.  Fires alert callbacks on events.
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional

from gateway_finder.utils.helpers import ping_host

log = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data types
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class PingResult:
    timestamp: float
    alive:     bool
    latency_ms: float


@dataclass
class MonitorStats:
    """Snapshot of current monitor statistics."""
    target:          str
    is_up:           bool          = False
    uptime_pct:      float         = 0.0
    loss_pct:        float         = 0.0
    avg_ms:          float         = 0.0
    min_ms:          float         = 0.0
    max_ms:          float         = 0.0
    jitter_ms:       float         = 0.0
    total_sent:      int           = 0
    total_received:  int           = 0
    last_change:     float         = 0.0    # epoch of last up↔down transition
    events:          List[str]     = field(default_factory=list)


AlertCallback = Callable[[str, str], None]   # (event_type, message)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Monitor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class GatewayMonitor:
    """
    Thread-based gateway monitor.

    Usage::

        mon = GatewayMonitor("192.168.1.1", interval=2)
        mon.on_alert(lambda etype, msg: print(f"ALERT [{etype}] {msg}"))
        mon.start()
        time.sleep(60)
        mon.stop()
        print(mon.get_stats())
    """

    def __init__(
        self,
        target: str,
        interval: float = 5.0,
        window: int = 60,       # samples kept in rolling window
        timeout: int = 2,
    ):
        self.target   = target
        self.interval = interval
        self.timeout  = timeout

        self._window: Deque[PingResult] = deque(maxlen=window)
        self._callbacks: List[AlertCallback] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()

        self._total_sent      = 0
        self._total_received  = 0
        self._last_state: Optional[bool] = None    # None = unknown
        self._last_change     = 0.0
        self._event_log: List[str] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def on_alert(self, callback: AlertCallback) -> None:
        """Register a callback for alert events."""
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start background monitoring thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name=f"monitor-{self.target}",
            daemon=True,
        )
        self._thread.start()
        log.info("Monitor started for %s (interval=%.1fs)", self.target, self.interval)

    def stop(self) -> None:
        """Stop the background thread and wait for it to finish."""
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 2)
        log.info("Monitor stopped for %s", self.target)

    def get_stats(self) -> MonitorStats:
        """Return a snapshot of current statistics."""
        with self._lock:
            samples = list(self._window)

        if not samples:
            return MonitorStats(target=self.target, events=list(self._event_log[-20:]))

        latencies = [s.latency_ms for s in samples if s.alive and s.latency_ms > 0]
        received  = sum(1 for s in samples if s.alive)
        sent      = len(samples)

        stats = MonitorStats(
            target         = self.target,
            is_up          = bool(samples[-1].alive) if samples else False,
            uptime_pct     = round(received / sent * 100, 1) if sent else 0.0,
            loss_pct       = round((sent - received) / sent * 100, 1) if sent else 0.0,
            avg_ms         = round(statistics.mean(latencies), 2) if latencies else 0.0,
            min_ms         = round(min(latencies), 2)             if latencies else 0.0,
            max_ms         = round(max(latencies), 2)             if latencies else 0.0,
            jitter_ms      = round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0.0,
            total_sent     = self._total_sent,
            total_received = self._total_received,
            last_change    = self._last_change,
            events         = list(self._event_log[-20:]),
        )
        return stats

    # ── Internal ──────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            t_start = time.monotonic()
            alive, ms = ping_host(self.target, count=1, timeout=self.timeout)

            result = PingResult(
                timestamp  = time.time(),
                alive      = alive,
                latency_ms = ms,
            )

            with self._lock:
                self._window.append(result)
                self._total_sent += 1
                if alive:
                    self._total_received += 1

            self._evaluate_state(alive, ms)

            # Sleep for the remainder of the interval
            elapsed = time.monotonic() - t_start
            sleep_for = max(0.0, self.interval - elapsed)
            self._stop_evt.wait(timeout=sleep_for)

    def _evaluate_state(self, alive: bool, ms: float) -> None:
        """Detect state transitions and trigger alerts."""
        prev = self._last_state

        if prev is None:
            # Initial state — no alert
            self._last_state  = alive
            self._last_change = time.time()
            return

        if alive != prev:
            self._last_state  = alive
            self._last_change = time.time()
            event_type = "UP" if alive else "DOWN"
            msg = (
                f"Gateway {self.target} is now {event_type}"
                + (f" (RTT {ms:.1f}ms)" if alive else "")
            )
            self._log_event(event_type, msg)
            self._fire(event_type, msg)
            return

        # High-latency alert (jitter > 100ms or avg > 200ms)
        with self._lock:
            recent = [s.latency_ms for s in list(self._window)[-5:] if s.alive]
        if len(recent) >= 3:
            avg = sum(recent) / len(recent)
            if avg > 200:
                msg = f"High latency on {self.target}: avg {avg:.1f}ms over last 5 probes"
                self._fire("HIGH_LATENCY", msg)

    def _log_event(self, etype: str, msg: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._last_change))
        self._event_log.append(f"[{ts}] {etype}: {msg}")
        log.info("%s — %s", etype, msg)

    def _fire(self, etype: str, msg: str) -> None:
        for cb in self._callbacks:
            try:
                cb(etype, msg)
            except Exception as exc:
                log.debug("Alert callback error: %s", exc)
