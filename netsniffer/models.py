"""Data models shared across the capture, analysis and UI layers.

Replacing the old `(num, time, src, dst, proto, sport, dport, info)` tuples
with a real dataclass gives us named-field access, type hints, and one
source of truth for "what is a captured packet" instead of positional
indices scattered through the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class ClassificationResult:
    """Pure classification output for a single sniffed packet.

    Produced by `netsniffer.capture.classifier.classify_packet`, which has
    no Tkinter or threading dependency and is therefore trivial to unit
    test with synthetic scapy packets.
    """

    protocol: str
    src: str
    dst: str
    sport: int | str = ""
    dport: int | str = ""
    info: str = ""
    # True for every packet that rides on a TCP segment, even when
    # `protocol` was refined to a more specific label like HTTP/HTTPS/SSH.
    # Lets the "TCP" stat card reflect *all* TCP traffic (as a user
    # expects) while the table/Info tab still shows the more useful,
    # specific classification.
    is_tcp: bool = False


@dataclass(slots=True)
class CapturedPacket:
    """A fully processed packet, ready for display, search and export."""

    num: int
    timestamp: datetime
    src: str
    dst: str
    protocol: str
    sport: int | str
    dport: int | str
    info: str
    details: str
    raw_payload: bytes = b""
    raw_scapy_packet: object = None  # kept for PCAP export via scapy.wrpcap
    is_tcp: bool = False

    def timestamp_str(self) -> str:
        return self.timestamp.strftime("%H:%M:%S")

    def as_row(self) -> tuple:
        """Tuple view used by the Treeview widget and CSV export."""
        return (
            self.num,
            self.timestamp_str(),
            self.src,
            self.dst,
            self.protocol,
            self.sport,
            self.dport,
            self.info,
        )

    def matches_query(self, query: str) -> bool:
        """Case-insensitive substring search across every displayed field."""
        if not query:
            return True
        query = query.strip().lower()
        return any(query in str(field_value).lower() for field_value in self.as_row())


@dataclass(slots=True)
class Alert:
    """A single mini-IDS finding (port scan, ARP spoofing, ...).

    Produced by `netsniffer.capture.alerts.AlertEngine`, which - like the
    classifier - has no Tkinter/threading dependency and is unit tested with
    synthetic scapy packets.
    """

    timestamp: datetime
    category: str          # e.g. "PORT_SCAN", "ARP_SPOOF"
    severity: str           # "info" | "warning" | "critical"
    message: str
    actor: str = ""          # the IP (or MAC) primarily responsible, for display

    def timestamp_str(self) -> str:
        return self.timestamp.strftime("%H:%M:%S")

    def as_line(self) -> str:
        icon = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(self.severity, "•")
        return f"[{self.timestamp_str()}] {icon} {self.category}: {self.message}"


@dataclass(slots=True)
class SessionStats:
    """Running per-protocol packet counters for the current capture session."""

    counts: dict[str, int] = field(default_factory=dict)

    def increment(self, protocol: str, known_keys: list[str]) -> None:
        self.counts["Total"] = self.counts.get("Total", 0) + 1
        if protocol in known_keys:
            self.counts[protocol] = self.counts.get(protocol, 0) + 1
        else:
            self.counts["Other"] = self.counts.get("Other", 0) + 1

    def bump_secondary(self, key: str) -> None:
        """Increment a counter as a secondary tally, without touching Total.

        Used so the "TCP" card can count every TCP-based packet even when
        `increment()` already credited a more specific label like HTTPS —
        otherwise Total would be counted twice for the same packet.
        """
        self.counts[key] = self.counts.get(key, 0) + 1

    def reset(self, known_keys: list[str]) -> None:
        self.counts = {key: 0 for key in known_keys}

    def get(self, key: str) -> int:
        return self.counts.get(key, 0)
