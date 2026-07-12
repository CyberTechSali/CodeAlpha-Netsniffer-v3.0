"""Centralized, non-code configuration for NetSniffer Pro.

Keeping colors / limits / filter definitions here (instead of scattered
across the GUI class) makes them easy to tweak without touching logic,
and easy to override from a config file later if needed.
"""

from __future__ import annotations

# --- App metadata (shown in the CLI welcome banner, --version, etc.) ----------

APP_NAME: str = "NetSniffer Pro"
APP_VERSION: str = "3.0"
APP_AUTHOR: str = "Ouchahed Salma"
APP_GITHUB: str = "@cybertechsali"
APP_ENGINE: str = "Python • Scapy"
APP_PLATFORM: str = "Linux / Windows"
APP_LICENSE: str = "MIT"
APP_TAGLINE: str = "Professional Network Packet Analysis Framework"

# --- Protocol stat keys & colors -------------------------------------------------

STAT_KEYS: list[str] = ["Total", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "SSH", "Other"]

STAT_COLORS: dict[str, str] = {
    "Total": "#89b4fa",
    "TCP": "#a6e3a1",
    "UDP": "#f9e2af",
    "ICMP": "#fab387",
    "ARP": "#94e2d5",
    "DNS": "#74c7ec",
    "HTTP": "#f5c2e7",
    "HTTPS": "#eba0ac",
    "SSH": "#f2cdcd",
    "Other": "#cba6f7",
}

# --- Capture filters ---------------------------------------------------------

# Friendly filter label -> BPF expression (None = no filter)
FILTER_MAP: dict[str, str | None] = {
    "All": None,
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "arp": "arp",
    "dns (port 53)": "port 53",
    "http (port 80)": "port 80",
    "https/tls (port 443)": "port 443",
}

# --- UI performance tuning ----------------------------------------------------

# Batch UI refresh interval, in milliseconds. Packets are queued from the
# capture thread and flushed into the Treeview on this cadence instead of
# one `after()` call per packet, which keeps the GUI responsive under load.
UI_FLUSH_INTERVAL_MS: int = 150

# Maximum number of rows kept *visible* in the Treeview at once. Older rows
# are pruned from the widget once this cap is exceeded, but every packet
# stays available in memory for CSV/PCAP export and searching.
MAX_VISIBLE_ROWS: int = 5000

# --- Mini-IDS (alert engine) tuning --------------------------------------------

# Port scan heuristic: a single source IP contacting at least this many
# *distinct* destination ports within PORT_SCAN_WINDOW_SECONDS is flagged.
# This is the classic signature of a sequential port scan (nmap -sS, etc.)
# and is very rare in legitimate traffic, where a client talks to a small,
# stable set of ports per remote host.
PORT_SCAN_DISTINCT_PORTS_THRESHOLD: int = 15
PORT_SCAN_WINDOW_SECONDS: float = 5.0
# Once triggered for a given source IP, don't re-alert for this many seconds
# even if the scan continues, to avoid flooding the alert log.
PORT_SCAN_ALERT_COOLDOWN_SECONDS: float = 20.0

# ARP spoofing heuristic: the same IP address being announced ("is-at") by
# more than one distinct MAC address is a classic ARP cache poisoning
# signature. A short grace period avoids false positives from normal DHCP
# lease changes or NIC failover immediately after the app starts.
ARP_SPOOF_ALERT_COOLDOWN_SECONDS: float = 20.0

# Maximum number of alert lines kept in the UI's alert log widget.
MAX_VISIBLE_ALERTS: int = 500

# --- Real-time charts tuning ----------------------------------------------------

# How much history (in seconds) the packets/second line chart displays.
CHART_HISTORY_SECONDS: int = 60
# Chart redraw cadence, in milliseconds. Kept coarser than UI_FLUSH_INTERVAL_MS
# because redrawing a matplotlib figure is much more expensive than a
# Treeview insert.
CHART_REDRAW_INTERVAL_MS: int = 1000

# --- Window defaults -----------------------------------------------------------

WINDOW_TITLE = "🛡️ NetSniffer Pro - Network Analyzer"
WINDOW_GEOMETRY = "1180x800"
WINDOW_MIN_SIZE = (1080, 740)

DEFAULT_APPEARANCE_MODE = "dark"
DEFAULT_COLOR_THEME = "blue"
