"""A small, pure heuristic intrusion-detection engine.

`AlertEngine` inspects each sniffed packet as it arrives and emits
`Alert` objects for two classic signatures:

1. **Port scanning** - a single source IP touching many distinct
   destination ports in a short time window (see
   `netsniffer.config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD`).
2. **ARP spoofing / cache poisoning** - the same IP address being
   claimed ("is-at") by more than one MAC address.

Deliberately has zero dependency on Tkinter or threading, exactly like
`netsniffer.capture.classifier`, so it can be unit tested with synthetic
scapy packets and a fake clock - no root privileges or live capture
required. It is *not* a replacement for a real IDS (no stateful TCP
tracking, no evasion resistance) - it's a best-effort teaching tool that
flags the two most common "someone is probing/spoofing this network"
patterns.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable

from scapy.all import ARP, IP, TCP, UDP, Packet

from netsniffer import config
from netsniffer.models import Alert

# Wall-clock provider, overridable in tests so time-window logic can be
# tested deterministically without real sleeps.
ClockFn = Callable[[], float]


class _PortScanDetector:
    """Flags a source IP once it has touched N distinct destination ports
    within a sliding time window."""

    def __init__(
        self,
        threshold: int = config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
        window_seconds: float = config.PORT_SCAN_WINDOW_SECONDS,
        cooldown_seconds: float = config.PORT_SCAN_ALERT_COOLDOWN_SECONDS,
        clock: ClockFn = None,
    ) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._cooldown = cooldown_seconds
        self._clock = clock or _monotonic_now
        # src_ip -> deque[(ts, dport)], most recent last
        self._recent: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alert_ts: dict[str, float] = {}

    def observe(self, src_ip: str, dport: int) -> Alert | None:
        now = self._clock()
        window = self._recent[src_ip]
        window.append((now, dport))

        cutoff = now - self._window
        while window and window[0][0] < cutoff:
            window.popleft()

        distinct_ports = {p for _, p in window}
        if len(distinct_ports) < self._threshold:
            return None

        last_alert = self._last_alert_ts.get(src_ip, -math.inf)
        if now - last_alert < self._cooldown:
            return None  # already warned recently, avoid flooding the log

        self._last_alert_ts[src_ip] = now
        return Alert(
            timestamp=datetime.now(),
            category="PORT_SCAN",
            severity="warning",
            actor=src_ip,
            message=(
                f"{src_ip} contacted {len(distinct_ports)} distinct ports "
                f"in under {self._window:.0f}s (possible port scan)"
            ),
        )


class _ArpSpoofDetector:
    """Flags an IP address that has been claimed ('is-at') by more than one
    distinct MAC address during the session."""

    def __init__(
        self,
        cooldown_seconds: float = config.ARP_SPOOF_ALERT_COOLDOWN_SECONDS,
        clock: ClockFn = None,
    ) -> None:
        self._cooldown = cooldown_seconds
        self._clock = clock or _monotonic_now
        self._ip_to_macs: dict[str, set[str]] = defaultdict(set)
        self._last_alert_ts: dict[str, float] = {}

    def observe(self, ip: str, mac: str) -> Alert | None:
        mac = mac.lower()
        known_macs = self._ip_to_macs[ip]
        is_new_conflicting_mac = bool(known_macs) and mac not in known_macs
        known_macs.add(mac)

        if not is_new_conflicting_mac:
            return None

        now = self._clock()
        last_alert = self._last_alert_ts.get(ip, -math.inf)
        if now - last_alert < self._cooldown:
            return None

        self._last_alert_ts[ip] = now
        macs_seen = ", ".join(sorted(known_macs))
        return Alert(
            timestamp=datetime.now(),
            category="ARP_SPOOF",
            severity="critical",
            actor=ip,
            message=f"{ip} is claimed by multiple MAC addresses: {macs_seen} (possible ARP spoofing)",
        )


def _monotonic_now() -> float:
    return time.monotonic()


class AlertEngine:
    """Feeds every sniffed packet through the available detectors and
    collects any resulting Alerts. Instantiate one per capture session."""

    def __init__(self, clock: ClockFn = None) -> None:
        self._port_scan = _PortScanDetector(clock=clock)
        self._arp_spoof = _ArpSpoofDetector(clock=clock)

    def feed(self, packet: Packet) -> list[Alert]:
        alerts: list[Alert] = []

        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2 and arp.psrc and arp.hwsrc:  # op 2 = is-at (ARP reply/announcement)
                alert = self._arp_spoof.observe(arp.psrc, arp.hwsrc)
                if alert:
                    alerts.append(alert)
            return alerts

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dport = None
            if packet.haslayer(TCP):
                dport = packet[TCP].dport
            elif packet.haslayer(UDP):
                dport = packet[UDP].dport
            if dport is not None:
                alert = self._port_scan.observe(src_ip, dport)
                if alert:
                    alerts.append(alert)

        return alerts
