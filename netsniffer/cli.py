"""NetSniffer Pro - CLI frontend.

Same architecture as the GUI (netsniffer.ui.app.ModernNetworkSnifferGUI):
both are just thin frontends around the shared, Tkinter-free core --
`PacketCapture` (capture/sniffer.py), `classify_packet` (capture/classifier.py),
`AlertEngine` (capture/alerts.py), `SessionStats`/`CapturedPacket` (models.py),
and the CSV/PCAP exporters (export/exporters.py). Nothing in this file
touches Tkinter; it only formats the same data for a terminal instead of a
Treeview.

Run with root / sudo (or a setcap'd binary, see scripts/setcap_linux.sh):

    sudo python3 main_cli.py -i eth0 -f "https/tls (port 443)"
    sudo python3 main_cli.py --list-interfaces
    sudo python3 main_cli.py -i eth0 -d 30 -o capture.pcap
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime

from netsniffer import config
from netsniffer.analysis.payload import get_hex_dump, get_payload_analysis
from netsniffer.capture.sniffer import PacketCapture
from netsniffer.export.exporters import export_csv, export_pcap
from netsniffer.models import Alert, CapturedPacket, SessionStats

logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.table import Table
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

try:
    import pyfiglet
    _HAS_PYFIGLET = True
except ImportError:
    _HAS_PYFIGLET = False

POLL_INTERVAL_SECONDS = 0.15

COLUMN_WIDTHS = {
    "No.": 6, "Time": 10, "Source": 17, "Destination": 17,
    "Protocol": 8, "Sport": 7, "Dport": 7, "Info": 34,
}

# Fallback (no `rich`) ANSI 24-bit color codes, derived from the same hex
# values the GUI uses for STAT_COLORS, so a plain terminal still gets
# roughly the same protocol color-coding as the CustomTkinter table.
_ANSI_RESET = "\033[0m"


def _hex_to_ansi_fg(hex_color: str) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return f"\033[38;2;{r};{g};{b}m"


def _colorize_plain(text: str, protocol: str) -> str:
    color = config.STAT_COLORS.get(protocol)
    if not color or not sys.stdout.isatty():
        return text
    return f"{_hex_to_ansi_fg(color)}{text}{_ANSI_RESET}"


_BLOCK_TITLE = (
    "╔══════════════════════════════════════╗\n"
    "║            N E T S N I F F E R        ║\n"
    "║                  P R O                ║\n"
    "╚══════════════════════════════════════╝"
)

_FEATURES = [
    "Live Network Packet Capture",
    "Multi-Protocol Detection (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, SSH)",
    "Real-Time Terminal Traffic View",
    "Payload Analysis (UTF-8, Hex Dump & Entropy) -- via --payload",
    "Heuristic Security Alerts (Port Scan, ARP Spoofing)",
    "Traffic Statistics & Session Summary",
    "CSV & PCAP Export",
    "Lightweight & Modular Architecture (shared core with the GUI)",
]

_DESCRIPTION = (
    "NetSniffer Pro CLI is a lightweight command-line network analyzer\n"
    "designed for network administrators, cybersecurity students, and\n"
    "penetration testers.\n\n"
    "It captures live network traffic, classifies protocols, inspects\n"
    "packet payloads, detects suspicious network activity using heuristic\n"
    "analysis, and exports captured traffic to CSV or PCAP for further\n"
    "investigation."
)


def _print_welcome_banner(console: "Console | None") -> None:
    """Printed exactly once, at CLI startup (see `main()`), before any
    command output. Centered and framed so it reads as a distinct
    "welcome screen" -- everything printed afterwards (the live packet
    table, alerts, summary) is plain left-aligned command output."""
    title = pyfiglet.figlet_format(config.APP_NAME.replace(" Pro", ""), font="standard") \
        if _HAS_PYFIGLET else _BLOCK_TITLE
    title = title.rstrip("\n")

    meta_lines = [
        ("Author", config.APP_AUTHOR),
        ("GitHub", config.APP_GITHUB),
        ("Version", config.APP_VERSION),
        ("Engine", config.APP_ENGINE),
        ("Platform", config.APP_PLATFORM),
        ("License", config.APP_LICENSE),
    ]

    if console:
        from rich import box as rich_box
        from rich.align import Align
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table as RichTable
        from rich.text import Text

        meta_table = RichTable.grid(padding=(0, 2))
        meta_table.add_column(justify="right")
        meta_table.add_column(justify="left")
        for label, value in meta_lines:
            meta_table.add_row(f"[dim]{label}[/dim]", f"[bold]: {value}[/bold]")

        body = Group(
            Align.center(Text(title, style="bold #89b4fa")),
            Align.center(Text(f"{config.APP_NAME} CLI v{config.APP_VERSION}", style="bold")),
            Align.center(Text(config.APP_TAGLINE, style="dim")),
            Text(""),
            Align.center(meta_table),
            Text(""),
            Align.center(Text("Run with --help to see all options.")),
            Align.center(Text("Example: sudo python3 main_cli.py -i eth0")),
            Text(""),
            Align.center(Text("Status : Ready ✓", style="bold #a6e3a1")),
        )
        console.print()
        console.print(Panel(body, box=rich_box.HEAVY, border_style="#2a2d3a", padding=(1, 3), width=min(console.width, 88)))
        console.print()
    else:
        import shutil
        width = min(shutil.get_terminal_size((80, 24)).columns, 100)
        dash = "-" * width

        lines: list[str] = [dash]
        for tl in title.split("\n"):
            lines.append(tl.center(width))
        lines.append(f"{config.APP_NAME} CLI v{config.APP_VERSION}".center(width))
        lines.append(config.APP_TAGLINE.center(width))
        lines.append("")
        for label, value in meta_lines:
            lines.append(f"{label:<10}: {value}".center(width))
        lines.append("")
        lines.append("Run with --help to see all options.".center(width))
        lines.append("Example: sudo python3 main_cli.py -i eth0".center(width))
        lines.append("")
        lines.append("Status : Ready".center(width))
        lines.append(dash)
        print("\n".join(lines))


def _print_about(console: "Console | None") -> None:
    if console:
        from rich.align import Align
        from rich.text import Text

        features_block = Text(justify="center")
        for i, feat in enumerate(_FEATURES):
            if i:
                features_block.append("\n")
            features_block.append("✓ ", style="bold #a6e3a1")
            features_block.append(feat)

        console.print(Align.center(Text("FEATURES", style="bold #89b4fa")))
        console.print()
        console.print(Align.center(features_block))
        console.print()
        console.print(Align.center(Text("DESCRIPTION", style="bold #89b4fa")))
        console.print()
        console.print(Align.center(Text(_DESCRIPTION, justify="center")))
        console.print()
    else:
        import shutil
        width = min(shutil.get_terminal_size((80, 24)).columns, 100)
        print("FEATURES".center(width))
        print()
        for feat in _FEATURES:
            print(f"[x] {feat}".center(width))
        print()
        print("DESCRIPTION".center(width))
        print()
        for dl in _DESCRIPTION.split("\n"):
            print(dl.center(width))
        print()


class CliSniffer:
    """Owns the terminal rendering loop around a `PacketCapture`."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.capture = PacketCapture(on_error=self._on_capture_error)
        self.stats = SessionStats()
        self.stats.reset(config.STAT_KEYS)
        self.all_packets: list[CapturedPacket] = []
        self._error: Exception | None = None
        self._stopped_by_user = False
        self.console = Console() if _HAS_RICH else None

    # -- capture lifecycle -------------------------------------------------
    def _on_capture_error(self, exc: Exception) -> None:
        self._error = exc

    def run(self) -> int:
        bpf_filter, active_filter_label = self._resolve_filter()
        iface = self.args.interface

        self._print_banner(iface, active_filter_label, bpf_filter)

        signal.signal(signal.SIGINT, self._handle_sigint)
        self.capture.start(iface=iface, bpf_filter=bpf_filter, active_filter_label=active_filter_label)

        if self._error is not None:
            self._print_error(str(self._error))
            return 1

        start_time = time.monotonic()
        try:
            while True:
                self._flush()
                if self._error is not None:
                    self._print_error(str(self._error))
                    break
                if self._stopped_by_user:
                    break
                if self.args.count and self.stats.get("Total") >= self.args.count:
                    break
                if self.args.duration and (time.monotonic() - start_time) >= self.args.duration:
                    break
                time.sleep(POLL_INTERVAL_SECONDS)
        finally:
            self.capture.stop()
            time.sleep(0.2)  # let the socket close and last packets land in the queue
            self._flush()

        self._print_summary()
        if self.args.output:
            self._export(self.args.output)
        return 0

    def _handle_sigint(self, _signum, _frame) -> None:
        self._stopped_by_user = True

    # -- filter resolution ---------------------------------------------------
    def _resolve_filter(self) -> tuple[str | None, str]:
        if self.args.bpf:
            return self.args.bpf, self.args.bpf
        label = self.args.filter or "All"
        if label not in config.FILTER_MAP:
            valid = ", ".join(config.FILTER_MAP.keys())
            self._print_error(f"Unknown preset '{label}'. Valid presets: {valid}")
            sys.exit(2)
        return config.FILTER_MAP[label], label

    # -- per-tick work ---------------------------------------------------
    def _flush(self) -> None:
        delayed_error = self.capture.poll_error()
        if delayed_error is not None:
            self._error = delayed_error

        for alert in self.capture.drain_alerts():
            self._print_alert(alert)

        new_packets = self.capture.drain()
        for pkt in new_packets:
            self.all_packets.append(pkt)
            self.stats.increment(pkt.protocol, config.STAT_KEYS)
            if pkt.is_tcp and pkt.protocol != "TCP":
                self.stats.bump_secondary("TCP")
            if not self.args.quiet:
                self._print_packet_row(pkt)
                if self.args.payload and pkt.raw_payload:
                    self._print_payload_analysis(pkt)

    # -- export ---------------------------------------------------------
    def _export(self, output_path: str) -> None:
        try:
            if output_path.lower().endswith(".pcap") or output_path.lower().endswith(".pcapng"):
                export_pcap(self.all_packets, output_path)
            else:
                export_csv(self.all_packets, output_path)
            self._print_info(f"Exported {len(self.all_packets)} packets to {output_path}")
        except Exception as exc:
            logger.exception("Export failed")
            self._print_error(f"Export failed: {exc}")

    # -- rendering: rich path ---------------------------------------------------
    def _print_banner(self, iface, active_filter_label, bpf_filter) -> None:
        if self.console:
            self.console.print(
                f"[bold #89b4fa]NetSniffer Pro[/bold #89b4fa] [dim](CLI)[/dim] — "
                f"iface=[bold]{iface or 'default'}[/bold] filter=[bold]{active_filter_label}[/bold]"
                f"{f' (bpf: {bpf_filter})' if bpf_filter else ''}"
            )
            self.console.print("[dim]Press Ctrl+C to stop.[/dim]\n")
            if not self.args.quiet:
                header = "  ".join(col.ljust(w) for col, w in COLUMN_WIDTHS.items())
                self.console.print(f"[bold]{header}[/bold]")
        else:
            print(f"NetSniffer Pro (CLI) - iface={iface or 'default'} filter={active_filter_label}"
                  f"{f' (bpf: {bpf_filter})' if bpf_filter else ''}")
            print("Press Ctrl+C to stop.\n")
            if not self.args.quiet:
                print("  ".join(col.ljust(w) for col, w in COLUMN_WIDTHS.items()))

    def _print_packet_row(self, pkt: CapturedPacket) -> None:
        cells = [
            str(pkt.num), pkt.timestamp_str(), pkt.src, pkt.dst,
            pkt.protocol, str(pkt.sport), str(pkt.dport), pkt.info,
        ]
        widths = list(COLUMN_WIDTHS.values())
        if self.console:
            color = config.STAT_COLORS.get(pkt.protocol, "#cdd6f4")
            row = "  ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths))
            self.console.print(f"[{color}]{row}[/{color}]")
        else:
            row = "  ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths))
            print(_colorize_plain(row, pkt.protocol))

    def _print_payload_analysis(self, pkt: CapturedPacket) -> None:
        hex_dump = get_hex_dump(pkt.raw_payload)
        analysis = get_payload_analysis(pkt.raw_payload)
        if self.console:
            self.console.print(f"[dim]{hex_dump}[/dim]")
            self.console.print(f"[#f9e2af]{analysis}[/#f9e2af]")
        else:
            print(hex_dump)
            print(analysis)

    def _print_alert(self, alert: Alert) -> None:
        line = alert.as_line()
        if self.console:
            style = {"info": "#89b4fa", "warning": "#f9e2af", "critical": "bold #f38ba8"}.get(alert.severity, "white")
            self.console.print(f"[{style}]{line}[/{style}]")
        else:
            print(line, file=sys.stderr)

    def _print_summary(self) -> None:
        if self.console:
            table = Table(title="Session Summary", show_header=True, header_style="bold #89b4fa")
            table.add_column("Protocol")
            table.add_column("Count", justify="right")
            for key in config.STAT_KEYS:
                color = config.STAT_COLORS.get(key, "white")
                table.add_row(f"[{color}]{key}[/{color}]", str(self.stats.get(key)))
            self.console.print()
            self.console.print(table)
        else:
            print("\n=== Session Summary ===")
            for key in config.STAT_KEYS:
                print(f"  {key:<8} {self.stats.get(key)}")

    def _print_error(self, message: str) -> None:
        if self.console:
            self.console.print(f"[bold #f38ba8]Error:[/bold #f38ba8] {message}")
        else:
            print(f"Error: {message}", file=sys.stderr)

    def _print_info(self, message: str) -> None:
        if self.console:
            self.console.print(f"[#a6e3a1]{message}[/#a6e3a1]")
        else:
            print(message)


def _list_interfaces() -> None:
    from scapy.all import get_if_list
    for name in get_if_list():
        print(name)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsniffer-cli",
        description="NetSniffer Pro - terminal packet sniffer (same capture/classification/alert/export core as the GUI).",
    )
    parser.add_argument("-i", "--interface", default=None, help="Network interface (default: scapy's default route interface)")
    parser.add_argument("-f", "--filter", default="All", choices=list(config.FILTER_MAP.keys()),
                         help="Named preset filter (same presets as the GUI's dropdown/chips). Default: All")
    parser.add_argument("--bpf", default=None, help="Raw BPF expression, overrides --filter (e.g. 'tcp and port 443')")
    parser.add_argument("-d", "--duration", type=float, default=None, help="Stop automatically after N seconds")
    parser.add_argument("-c", "--count", type=int, default=None, help="Stop automatically after N packets")
    parser.add_argument("-o", "--output", default=None,
                         help="Export captured packets on exit; .pcap/.pcapng -> PCAP, anything else -> CSV")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress the live per-packet table; only print alerts + final summary")
    parser.add_argument("-p", "--payload", action="store_true",
                         help="Print a hex dump + entropy/UTF-8 analysis of each packet's payload (same engine as the GUI's Payload tab)")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--no-banner", action="store_true", help="Skip the welcome banner")
    parser.add_argument("--about", action="store_true",
                         help="Print full details (features + description) and exit")
    parser.add_argument("--version", action="version", version=f"{config.APP_NAME} CLI v{config.APP_VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    from netsniffer.logging_setup import configure_logging
    configure_logging()

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        _print_welcome_banner(Console() if _HAS_RICH else None)

    if args.about:
        _print_about(Console() if _HAS_RICH else None)
        return 0

    if args.list_interfaces:
        _list_interfaces()
        return 0

    if not _HAS_RICH:
        print("[i] Tip: 'pip install rich' for a colorized, nicer-looking live table (optional).", file=sys.stderr)

    return CliSniffer(args).run()


if __name__ == "__main__":
    sys.exit(main())
