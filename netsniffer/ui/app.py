"""Main GUI application for NetSniffer Pro.

This module is now UI-only: all packet classification, capture threading,
payload analysis, and export logic live in dedicated modules
(`netsniffer.capture`, `netsniffer.analysis`, `netsniffer.export`). This
class is responsible for building widgets and reacting to user actions.
"""

from __future__ import annotations

import logging
import sys
import time
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from PIL import Image, ImageTk
from scapy.all import get_if_list

from netsniffer import config
from netsniffer.assets import icon_ico_path, icon_png_path
from netsniffer.analysis.payload import decode_utf8_best_effort, get_hex_dump, get_payload_analysis
from netsniffer.analysis.traffic_rate import RateTracker
from netsniffer.capture.sniffer import PacketCapture
from netsniffer.export.exporters import export_csv, export_pcap
from netsniffer.models import Alert, CapturedPacket, SessionStats
from netsniffer.ui.save_dialog import ask_save_file, show_themed_message

logger = logging.getLogger(__name__)

ctk.set_appearance_mode(config.DEFAULT_APPEARANCE_MODE)
ctk.set_default_color_theme(config.DEFAULT_COLOR_THEME)

# matplotlib figures should blend into the dark CTk theme rather than
# showing a jarring white default background.
plt.style.use("dark_background")


class ModernNetworkSnifferGUI(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        ctk.set_widget_scaling(0.9)
        ctk.set_window_scaling(0.9)

        self.title(config.WINDOW_TITLE)
        self.geometry(config.WINDOW_GEOMETRY)
        self.minsize(*config.WINDOW_MIN_SIZE)
        self.configure(fg_color="#0d0f17")
        self._load_logo_image()
        self._set_window_icon()

        # Capture state
        self.capture = PacketCapture(on_error=self._on_capture_error)
        self.active_filter_label = "All"
        self.stats = SessionStats()
        self.stats.reset(config.STAT_KEYS)

        # Storage: every captured packet, keyed by packet number.
        self.packets: dict[int, CapturedPacket] = {}
        self.all_packets_ordered: list[CapturedPacket] = []

        # Mini-IDS alert log for this session.
        self.alerts: list[Alert] = []

        # Real-time packets/sec history for the Charts tab.
        self.rate_tracker = RateTracker(history_seconds=config.CHART_HISTORY_SECONDS)

        # Search state
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)

        self.build_ui()
        self._flush_capture_queue()  # kick off the polling loop
        self._redraw_charts()  # kick off the (coarser-cadence) chart loop

    def _load_logo_image(self) -> None:
        """Load the shield logo once as a CTkImage, reused across the UI.

        CTkImage (rather than plain PhotoImage) keeps the logo crisp on
        HiDPI displays and is what CTkLabel/CTkButton expect for `image=`.
        """
        try:
            pil_image = Image.open(icon_png_path())
            self._logo_image = ctk.CTkImage(light_image=pil_image, dark_image=pil_image, size=(40, 40))
        except Exception:
            logger.warning("Could not load sidebar logo image; continuing without it.", exc_info=True)
            self._logo_image = None

    def _set_window_icon(self) -> None:
        """Apply the NetSniffer Pro shield logo as the window/taskbar icon.

        `iconbitmap` (native .ico) is preferred on Windows; everywhere else
        (Linux/X11, macOS) we fall back to `iconphoto` with a PNG loaded
        through Pillow, which Tk's PhotoImage can't decode on its own.
        Missing/corrupt asset files are non-fatal — the app still runs with
        the default Tk icon.

        CustomTkinter is known to reset the window icon back to the default
        Tk icon a moment after the window is first drawn (it touches the
        native title bar itself, e.g. for Windows dark-mode titles). We
        reapply once more shortly after startup to win that race.
        """
        try:
            if sys.platform.startswith("win"):
                self.iconbitmap(str(icon_ico_path()))
            else:
                icon_image = Image.open(icon_png_path())
                self._icon_photo = ImageTk.PhotoImage(icon_image)  # keep a ref, GC-safe
                self.iconphoto(True, self._icon_photo)
        except Exception:
            logger.warning("Could not load application icon; continuing with default.", exc_info=True)
            return

        for delay_ms in (150, 400, 800, 1500):
            self.after(delay_ms, self._reapply_window_icon)

    def _reapply_window_icon(self) -> None:
        try:
            if sys.platform.startswith("win"):
                self.iconbitmap(str(icon_ico_path()))
            else:
                self.iconphoto(True, self._icon_photo)
        except Exception:
            logger.warning("Could not reapply application icon.", exc_info=True)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

        self._build_toolbar()
        self._build_sidebar()
        self._build_main_area()
        self._build_status_bar()

    def _build_toolbar(self) -> None:
        """Top toolbar: brand, capture controls, interface, live packet count.

        Inspired by the classic sniffer-tool layout (brand mark top-left,
        primary actions + interface/status readouts on one bar, protocol
        quick-filters on the row just under it — see `_build_search_bar`).
        """
        self.toolbar = ctk.CTkFrame(self, height=58, corner_radius=0, fg_color="#11131c")
        self.toolbar.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.toolbar.grid_propagate(False)

        brand = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        brand.pack(side="left", padx=(16, 24), pady=6)
        ctk.CTkLabel(
            brand, image=self._logo_image, text=" NetSniffer Pro",
            compound="left", font=ctk.CTkFont(size=16, weight="bold"), text_color="#e6e9f0"
        ).pack(side="left")

        controls = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        controls.pack(side="left", pady=8)

        self.start_btn = ctk.CTkButton(
            controls, text="▶ Start", width=90, fg_color="#2eb872", hover_color="#1d8f53",
            font=ctk.CTkFont(weight="bold"), command=self.start_sniffing)
        self.start_btn.pack(side="left", padx=(0, 6))

        self.stop_btn = ctk.CTkButton(
            controls, text="■ Stop", width=90, fg_color="#e05252", hover_color="#b83535",
            font=ctk.CTkFont(weight="bold"), command=self.stop_sniffing, state="disabled")
        self.stop_btn.pack(side="left", padx=6)

        self.clear_btn = ctk.CTkButton(
            controls, text="🗑 Clear", width=80, fg_color="#2a2d3a", hover_color="#3a3e4f",
            command=self.clear_table)
        self.clear_btn.pack(side="left", padx=6)

        iface_block = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        iface_block.pack(side="left", padx=24, pady=8)
        try:
            interfaces = get_if_list()
        except Exception:
            logger.exception("Failed to list network interfaces")
            interfaces = []
        ctk.CTkLabel(iface_block, text="Interface:", font=ctk.CTkFont(size=11), text_color="gray").pack(side="left", padx=(0, 6))
        self.iface_combo = ctk.CTkComboBox(
            iface_block, values=interfaces if interfaces else ["No interface found"],
            width=150, height=26, fg_color="#1c1f2b", button_color="#2a2d3a", border_color="#2a2d3a")
        self.iface_combo.pack(side="left")
        if interfaces:
            self.iface_combo.set(interfaces[0])

        readouts = ctk.CTkFrame(self.toolbar, fg_color="transparent")
        readouts.pack(side="right", padx=16, pady=8)
        ctk.CTkLabel(
            readouts, text="Promiscuous: ON", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94e2d5"
        ).pack(side="right", padx=(16, 0))
        self.toolbar_count_label = ctk.CTkLabel(
            readouts, text="Packets: 0", font=ctk.CTkFont(size=12, weight="bold"), text_color="#89b4fa")
        self.toolbar_count_label.pack(side="right", padx=(16, 0))

    def _build_sidebar(self) -> None:
        self.sidebar_frame = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color="#151824")
        self.sidebar_frame.grid(row=1, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        ctk.CTkLabel(
            self.sidebar_frame, text="Display Filter", anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#89b4fa"
        ).grid(row=0, column=0, padx=20, pady=(18, 4), sticky="w")

        ctk.CTkLabel(self.sidebar_frame, text="Quick protocol filters:", anchor="w",
                     font=ctk.CTkFont(size=10), text_color="gray").grid(
            row=1, column=0, padx=20, pady=(2, 4), sticky="w")

        self._build_protocol_chips(self.sidebar_frame, row=2)

        ctk.CTkLabel(self.sidebar_frame, text="Preset:", anchor="w").grid(
            row=3, column=0, padx=20, pady=(10, 0), sticky="w")

        self.filter_combo = ctk.CTkComboBox(
            self.sidebar_frame, values=list(config.FILTER_MAP.keys()), width=200)
        self.filter_combo.grid(row=4, column=0, padx=20, pady=(3, 10))
        self.filter_combo.set("All")

        # Mini-IDS badge: always visible in the sidebar, not just when the
        # Alerts tab happens to be open.
        self.alert_badge = ctk.CTkLabel(
            self.sidebar_frame, text="🛡 No alerts", font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#a6e3a1")
        self.alert_badge.grid(row=5, column=0, padx=20, pady=(10, 0))

    def _build_protocol_chips(self, parent, row: int) -> None:
        """Small pill buttons for one-click protocol filtering.

        Mirrors the quick-filter chip row from classic packet-analyzer
        UIs: click a protocol to fill in (and select) the matching preset
        below, instead of opening the dropdown. Each chip is tinted with
        that protocol's stat/badge color for quick visual scanning.
        """
        chips_frame = ctk.CTkFrame(parent, fg_color="transparent")
        chips_frame.grid(row=row, column=0, padx=14, pady=(0, 4), sticky="w")

        # (short chip text, FILTER_MAP preset key, STAT_COLORS color key)
        chip_defs = [
            ("TCP", "tcp", "TCP"),
            ("UDP", "udp", "UDP"),
            ("HTTP", "http (port 80)", "HTTP"),
            ("HTTPS", "https/tls (port 443)", "HTTPS"),
            ("DNS", "dns (port 53)", "DNS"),
            ("ARP", "arp", "ARP"),
            ("ICMP", "icmp", "ICMP"),
        ]
        for i, (chip_text, preset_label, color_key) in enumerate(chip_defs):
            color = config.STAT_COLORS.get(color_key, "#89b4fa")
            chip = ctk.CTkButton(
                chips_frame, text=chip_text, width=58, height=22,
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#1c1f2b", hover_color="#2a2d3a", border_width=1, border_color=color,
                text_color=color, command=lambda lbl=preset_label: self._on_filter_chip_click(lbl))
            r, c = divmod(i, 3)
            chip.grid(row=r, column=c, padx=3, pady=3, sticky="w")

    def _on_filter_chip_click(self, preset_label: str) -> None:
        self.filter_combo.set(preset_label)

    def _build_main_area(self) -> None:
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=1, column=1, sticky="nsew", padx=15, pady=15)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        self._build_stats_dashboard()
        self._build_search_bar()

        # Table (packet list) and the details tabview below it share a
        # draggable vertical splitter, so the table isn't stuck showing
        # only ~4 rows — drag the handle to trade space between the two.
        self.content_paned = tk.PanedWindow(
            self.main_frame, orient="vertical", sashwidth=6, sashrelief="flat",
            bg="#2a2d3a", bd=0, opaqueresize=True)
        self.content_paned.grid(row=2, column=0, sticky="nsew")

        self._build_table()
        self._build_details_tabs()

    def _build_stats_dashboard(self) -> None:
        self.stats_frame = ctk.CTkFrame(self.main_frame)
        self.stats_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        cols = 5
        for i in range(cols):
            self.stats_frame.grid_columnconfigure(i, weight=1)

        self.stat_cards: dict[str, ctk.CTkLabel] = {}
        for index, name in enumerate(config.STAT_KEYS):
            color = config.STAT_COLORS[name]
            r, c = divmod(index, cols)
            card = ctk.CTkFrame(self.stats_frame, fg_color="#2e303e", corner_radius=8)
            card.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")

            ctk.CTkLabel(card, text=name.upper(), font=ctk.CTkFont(size=10, weight="bold"),
                         text_color="gray").pack(pady=(5, 0))
            val_lbl = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=20, weight="bold"), text_color=color)
            val_lbl.pack(pady=(2, 5))
            self.stat_cards[name] = val_lbl

    def _build_search_bar(self) -> None:
        self.search_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        # Native CTkEntry placeholder (crisp, correctly inset, doesn't
        # intercept clicks) instead of a `textvariable` + overlay label.
        # CTkEntry's built-in placeholder never activates when a
        # `textvariable` is also supplied, so instead we bind <KeyRelease>
        # to push the entry's text into `search_var` ourselves; everything
        # downstream (search_var's trace -> _on_search_change) keeps
        # working exactly as before.
        self.search_entry = ctk.CTkEntry(
            self.search_frame, width=320, height=30,
            placeholder_text="Search IP, protocol, port...",
            placeholder_text_color="#6c7086",
            fg_color="#1c1f2b", border_color="#2a2d3a", border_width=1,
            text_color="#cdd6f4", font=ctk.CTkFont(size=12))
        self.search_entry.pack(side="left", padx=(5, 10))
        self.search_entry.bind("<KeyRelease>", self._on_search_entry_keyrelease)

        ctk.CTkButton(
            self.search_frame, text="✕", width=28, height=28,
            fg_color="#4f5b66", hover_color="#343d46",
            command=self._clear_search
        ).pack(side="left")

        self.search_status_lbl = ctk.CTkLabel(
            self.search_frame, text="", font=ctk.CTkFont(size=11, slant="italic"), text_color="#89b4fa")
        self.search_status_lbl.pack(side="left", padx=10)

    def _on_search_entry_keyrelease(self, _event=None) -> None:
        self.search_var.set(self.search_entry.get())

    def _clear_search(self) -> None:
        self.search_entry.delete(0, tk.END)
        self.search_var.set("")

    def _build_table(self) -> None:
        self.table_container = ctk.CTkFrame(self.content_paned)
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(0, weight=1)

        self.tree_style = ttk.Style()
        self.tree_style.theme_use("default")
        self.tree_style.configure("Treeview",
            background="#12141c", foreground="#cdd6f4", fieldbackground="#12141c",
            rowheight=26, borderwidth=0, font=("Consolas", 10))
        self.tree_style.map("Treeview", background=[("selected", "#2a2d3a")])
        self.tree_style.configure("Treeview.Heading",
            background="#1c1f2b", foreground="#cdd6f4", relief="flat", font=("Consolas", 10, "bold"))
        self.tree_style.map("Treeview.Heading", background=[("active", "#45475a")])

        columns = ("num", "time", "src", "dst", "proto", "sport", "dport", "info")
        self.tree = ttk.Treeview(self.table_container, columns=columns, show="headings", style="Treeview")
        self.tree.grid(row=0, column=0, sticky="nsew")

        headers = {
            "num": "No.", "time": "Time", "src": "Source IP", "dst": "Destination IP",
            "proto": "Protocol", "sport": "Src Port", "dport": "Dst Port", "info": "Info"
        }
        widths = {"num": 50, "time": 90, "src": 150, "dst": 150, "proto": 80,
                  "sport": 80, "dport": 80, "info": 220}
        for col in columns:
            self.tree.heading(col, text=headers[col])
            anchor = tk.W if col == "info" else tk.CENTER
            self.tree.column(col, width=widths[col], anchor=anchor)

        self.scrollbar = ctk.CTkScrollbar(self.table_container, orientation="vertical", command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.tree.bind("<Double-1>", self.show_packet_details)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        for proto_name in ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "SSH", "OTHER"]:
            self.tree.tag_configure(proto_name, foreground=config.STAT_COLORS.get(
                proto_name if proto_name != "OTHER" else "Other", "#cdd6f4"))

        self.content_paned.add(self.table_container, minsize=100, height=320, stretch="always")

    def _build_details_tabs(self) -> None:
        self.details_tab = ctk.CTkTabview(
            self.content_paned, command=self.on_tab_change,
            fg_color="#12141c",
            segmented_button_fg_color="#151824",
            segmented_button_selected_color="#1c3a5e",
            segmented_button_selected_hover_color="#204468",
            segmented_button_unselected_color="#151824",
            segmented_button_unselected_hover_color="#1c1f2b",
            text_color="#cdd6f4",
        )
        self.content_paned.add(self.details_tab, minsize=160, height=270, stretch="always")

        self.tab_info = self.details_tab.add("ℹ️ Info")
        self.tab_payload = self.details_tab.add("📝 Payload")
        self.tab_alerts = self.details_tab.add("🛡 Alerts")
        self.tab_charts = self.details_tab.add("📈 Charts")
        self.tab_exports = self.details_tab.add("💾 Exports & Stats")

        self.info_text = ctk.CTkTextbox(self.tab_info, font=("Consolas", 11), wrap="word", fg_color="#0d0f17", text_color="#cdd6f4")
        self.info_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.info_text.insert("0.0", "Double-click on a row to see detailed packet analysis.")
        self.info_text.configure(state="disabled")

        self.payload_controls = ctk.CTkFrame(self.tab_payload, fg_color="transparent", height=35)
        self.payload_controls.pack(fill="x", padx=5, pady=(5, 0))

        self.payload_mode_btn = ctk.CTkSegmentedButton(
            self.payload_controls, values=["UTF-8 Text", "Hex Dump", "Analysis"], command=self.update_payload_view)
        self.payload_mode_btn.pack(side="left", padx=5)
        self.payload_mode_btn.set("UTF-8 Text")

        self.payload_text = ctk.CTkTextbox(self.tab_payload, font=("Consolas", 10), wrap="none", fg_color="#0d0f17", text_color="#cdd6f4")
        self.payload_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.payload_text.insert("0.0", "Select a packet to visualize its payload.")
        self.payload_text.configure(state="disabled")

        self._build_alerts_tab()
        self._build_charts_tab()
        self._build_exports_tab()

    def _build_alerts_tab(self) -> None:
        controls = ctk.CTkFrame(self.tab_alerts, fg_color="transparent", height=30)
        controls.pack(fill="x", padx=5, pady=(5, 0))
        ctk.CTkLabel(
            controls, text="Heuristic mini-IDS: flags port scans and ARP spoofing. Best-effort, not a full IDS.",
            font=ctk.CTkFont(size=10, slant="italic"), text_color="gray"
        ).pack(side="left")
        ctk.CTkButton(
            controls, text="Clear", width=60, height=22, fg_color="#4f5b66", hover_color="#343d46",
            command=self.clear_alerts
        ).pack(side="right")

        self.alerts_text = ctk.CTkTextbox(self.tab_alerts, font=("Consolas", 10), wrap="word", fg_color="#0d0f17", text_color="#cdd6f4")
        self.alerts_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.alerts_text.insert("0.0", "No alerts yet. Start a capture to begin monitoring.")
        self.alerts_text.configure(state="disabled")
        self.alerts_text.tag_config("critical", foreground="#f38ba8")
        self.alerts_text.tag_config("warning", foreground="#f9e2af")
        self.alerts_text.tag_config("info", foreground="#89b4fa")

    def _build_charts_tab(self) -> None:
        # One shared Figure with two subplots: packets/sec over the last
        # CHART_HISTORY_SECONDS seconds, and the current protocol breakdown.
        self.charts_figure = Figure(figsize=(9, 2.6), dpi=100, facecolor="#1e1e2e")
        self.rate_ax = self.charts_figure.add_subplot(1, 2, 1)
        self.proto_ax = self.charts_figure.add_subplot(1, 2, 2)
        self.charts_figure.subplots_adjust(left=0.08, right=0.97, top=0.88, bottom=0.2, wspace=0.35)

        self.charts_canvas = FigureCanvasTkAgg(self.charts_figure, master=self.tab_charts)
        self.charts_canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
        self._draw_charts()  # initial empty draw

    def _build_exports_tab(self) -> None:
        self.exports_grid = ctk.CTkScrollableFrame(self.tab_exports, fg_color="transparent")
        self.exports_grid.pack(fill="both", expand=True, padx=10, pady=10)
        self.exports_grid.columnconfigure(0, weight=3)
        self.exports_grid.columnconfigure(1, weight=2)
        self.exports_grid.rowconfigure(0, weight=1)

        left = ctk.CTkFrame(self.exports_grid, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.rowconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        csv_card = ctk.CTkFrame(left, fg_color="#151824", border_width=1, border_color="#2a2d3a")
        csv_card.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        ctk.CTkLabel(csv_card, text="CSV Report", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#e6e9f0").pack(anchor="w", padx=15, pady=(10, 2))
        ctk.CTkLabel(csv_card, text="Export all grid entries into CSV spreadsheet format.",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w", padx=15, pady=(0, 10))
        ctk.CTkButton(
            csv_card, text="⬇  Export as CSV", font=ctk.CTkFont(size=12, weight="bold"),
            width=160, height=30, corner_radius=6, fg_color="#2563eb", hover_color="#1d4ed8", text_color="#ffffff",
            cursor="hand2", command=self.export_csv
        ).pack(anchor="w", padx=15, pady=(0, 12))

        pcap_card = ctk.CTkFrame(left, fg_color="#151824", border_width=1, border_color="#2a2d3a")
        pcap_card.grid(row=1, column=0, sticky="nsew", pady=(5, 0))
        ctk.CTkLabel(pcap_card, text="PCAP Capture", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#e6e9f0").pack(anchor="w", padx=15, pady=(10, 2))
        ctk.CTkLabel(pcap_card, text="Export raw packet data in Wireshark (.pcap) format.",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w", padx=15, pady=(0, 10))
        ctk.CTkButton(
            pcap_card, text="⬇  Export as PCAP", font=ctk.CTkFont(size=12, weight="bold"),
            width=160, height=30, corner_radius=6, fg_color="#2563eb", hover_color="#1d4ed8", text_color="#ffffff",
            cursor="hand2", command=self.export_pcap
        ).pack(anchor="w", padx=15, pady=(0, 12))

        right = ctk.CTkFrame(self.exports_grid, border_width=1, border_color="#2a2d3a", fg_color="#151824")
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        ctk.CTkLabel(right, text="Session Summary", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#89b4fa").pack(anchor="w", padx=15, pady=(10, 5))
        self.stats_summary_label = ctk.CTkLabel(
            right, text="No session data available.\nStart capturing packets first.",
            justify="left", font=ctk.CTkFont(family="Consolas", size=11), anchor="w", text_color="#cdd6f4")
        self.stats_summary_label.pack(fill="both", expand=True, padx=15, pady=(0, 10))

    def _build_status_bar(self) -> None:
        self.status_bar = ctk.CTkFrame(self, height=25, corner_radius=0)
        self.status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.status_label = ctk.CTkLabel(self.status_bar, text="Status: Inactive", text_color="#f38ba8",
                                          font=ctk.CTkFont(size=11, weight="bold"))
        self.status_label.pack(side="left", padx=20)

    # ------------------------------------------------------------------
    # Appearance
    # ------------------------------------------------------------------
    def change_appearance_mode(self, new_mode: str) -> None:
        ctk.set_appearance_mode(new_mode)
        is_dark = new_mode.lower() != "light"
        bg_color = "#2e303e" if is_dark else "#f2f2f2"
        for card_val in self.stat_cards.values():
            card_val.master.configure(fg_color=bg_color)

        self.configure(fg_color="#0d0f17" if is_dark else "#eceef2")
        self.toolbar.configure(fg_color="#11131c" if is_dark else "#e2e4ea")
        self.sidebar_frame.configure(fg_color="#151824" if is_dark else "#e8eaf0")
        self.content_paned.configure(bg="#2a2d3a" if is_dark else "#c7cad1")

        if not is_dark:
            self.tree_style.configure("Treeview", background="#ffffff", foreground="#313244", fieldbackground="#ffffff")
            self.tree_style.configure("Treeview.Heading", background="#e6e6e6", foreground="#313244")
        else:
            self.tree_style.configure("Treeview", background="#12141c", foreground="#cdd6f4", fieldbackground="#12141c")
            self.tree_style.configure("Treeview.Heading", background="#1c1f2b", foreground="#cdd6f4")

    # ------------------------------------------------------------------
    # Live search / filtering
    # ------------------------------------------------------------------
    def _on_search_change(self, *_args) -> None:
        query = self.search_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        visible_count = 0
        for pkt in self.all_packets_ordered:
            if pkt.matches_query(query):
                self.tree.insert("", tk.END, values=pkt.as_row(), tags=(pkt.protocol,))
                visible_count += 1

        if self.tree.get_children():
            self.tree.yview_moveto(1)

        self._update_search_status_label(visible_count)

    def _update_search_status_label(self, visible_count: int | None = None) -> None:
        total_count = len(self.all_packets_ordered)
        query = self.search_var.get().strip()

        if not query:
            self.search_status_lbl.configure(text="")
            return

        if visible_count is None:
            visible_count = sum(1 for pkt in self.all_packets_ordered if pkt.matches_query(query))

        self.search_status_lbl.configure(text=f"Showing {visible_count} of {total_count} packets")

    # ------------------------------------------------------------------
    # Payload viewer
    # ------------------------------------------------------------------
    def update_payload_view(self, mode: str | None = None) -> None:
        if mode is None:
            mode = self.payload_mode_btn.get()

        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        try:
            num = int(item["values"][0])
        except (ValueError, IndexError):
            return

        pkt = self.packets.get(num)
        if pkt is None:
            return

        self.payload_text.configure(state="normal")
        self.payload_text.delete("0.0", tk.END)

        if mode == "UTF-8 Text":
            self.payload_text.insert("0.0", decode_utf8_best_effort(pkt.raw_payload))
        elif mode == "Hex Dump":
            self.payload_text.insert("0.0", get_hex_dump(pkt.raw_payload))
        elif mode == "Analysis":
            self.payload_text.insert("0.0", get_payload_analysis(pkt.raw_payload))

        self.payload_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Real-time charts
    # ------------------------------------------------------------------
    def _draw_charts(self) -> None:
        self.rate_ax.clear()
        xs, ys = self.rate_tracker.series(time.time())
        self.rate_ax.plot(xs, ys, color="#89b4fa", linewidth=1.5)
        self.rate_ax.fill_between(xs, ys, color="#89b4fa", alpha=0.15)
        self.rate_ax.set_title("Packets / sec", fontsize=9, color="#cdd6f4")
        self.rate_ax.set_xlim(-config.CHART_HISTORY_SECONDS, 0)
        self.rate_ax.set_ylim(bottom=0)
        self.rate_ax.tick_params(labelsize=7, colors="#a6adc8")
        self.rate_ax.set_facecolor("#1e1e2e")
        for spine in self.rate_ax.spines.values():
            spine.set_color("#45475a")

        self.proto_ax.clear()
        proto_keys = [k for k in config.STAT_KEYS if k not in ("Total",)]
        values = [self.stats.get(k) for k in proto_keys]
        colors = [config.STAT_COLORS.get(k, "#cdd6f4") for k in proto_keys]
        if any(values):
            self.proto_ax.bar(proto_keys, values, color=colors)
        self.proto_ax.set_title("Protocol distribution", fontsize=9, color="#cdd6f4")
        self.proto_ax.tick_params(labelsize=7, colors="#a6adc8", rotation=45)
        self.proto_ax.set_facecolor("#1e1e2e")
        for spine in self.proto_ax.spines.values():
            spine.set_color("#45475a")

        self.charts_canvas.draw_idle()

    def _redraw_charts(self) -> None:
        """Runs on its own, coarser cadence (CHART_REDRAW_INTERVAL_MS) since
        redrawing a matplotlib figure is far more expensive than a Treeview
        insert. Only redraws while the Charts tab is actually visible."""
        if self.details_tab.get() == "📈 Charts":
            self._draw_charts()
        self.after(config.CHART_REDRAW_INTERVAL_MS, self._redraw_charts)

    # ------------------------------------------------------------------
    # Session-wide stats
    # ------------------------------------------------------------------
    def on_tab_change(self) -> None:
        if self.details_tab.get() == "💾 Exports & Stats":
            self.update_session_stats()

    def update_session_stats(self) -> None:
        if not self.all_packets_ordered:
            self.stats_summary_label.configure(text="No session data available.\nStart capturing packets first.")
            return

        src_ips = [pkt.src for pkt in self.all_packets_ordered if pkt.protocol != "ARP"]
        dst_ips = [pkt.dst for pkt in self.all_packets_ordered if pkt.protocol != "ARP"]

        if not src_ips:
            self.stats_summary_label.configure(text="No IP packets captured yet (ARP traffic has no IP layer).")
            return

        from collections import Counter
        unique_src = len(set(src_ips))
        unique_dst = len(set(dst_ips))
        top_src = Counter(src_ips).most_common(1)[0][0]
        top_dst = Counter(dst_ips).most_common(1)[0][0]
        iface = self.iface_combo.get()

        summary = (
            f" Active interface: {iface}\n\n"
            f" Unique Source IPs: {unique_src}\n"
            f" Unique Dest IPs: {unique_dst}\n\n"
            f" Top Source IP: {top_src}\n"
            f" Top Destination IP: {top_dst}"
        )
        self.stats_summary_label.configure(text=summary)

    # ------------------------------------------------------------------
    # Capture logic
    # ------------------------------------------------------------------
    def start_sniffing(self) -> None:
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="Status: Sniffing active...", text_color="#a6e3a1")
        self.iface_combo.configure(state="disabled")
        self.filter_combo.configure(state="disabled")

        # `active_filter_label` is what the classifier looks at for the
        # "tcp" special-case (see classifier.classify_packet).
        self.active_filter_label = self.filter_combo.get()
        bpf_filter = config.FILTER_MAP.get(self.active_filter_label)

        iface = self.iface_combo.get()
        if iface in ("No interface found", ""):
            iface = None

        self.capture.start(iface=iface, bpf_filter=bpf_filter, active_filter_label=self.active_filter_label)

    def stop_sniffing(self) -> None:
        self.capture.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.iface_combo.configure(state="normal")
        self.filter_combo.configure(state="normal")
        self.status_label.configure(text="Status: Stopped", text_color="#f38ba8")

    def _on_capture_error(self, exc: Exception) -> None:
        message = str(exc) or exc.__class__.__name__
        if isinstance(exc, PermissionError):
            message = "Insufficient permissions.\nOn Kali Linux, run the program with 'sudo'."

        def show_and_reset():
            show_themed_message(self, "Error", message, kind="error")
            self.stop_sniffing()

        self.after(0, show_and_reset)

    def _flush_capture_queue(self) -> None:
        """Batch-drain the capture queue and update the UI once, instead of
        scheduling a Tkinter callback per packet."""
        new_packets = self.capture.drain()
        new_alerts = self.capture.drain_alerts()

        delayed_error = self.capture.poll_error()
        if delayed_error is not None:
            self._on_capture_error(delayed_error)

        if new_alerts:
            self._handle_new_alerts(new_alerts)

        if new_packets:
            for pkt in new_packets:
                self.packets[pkt.num] = pkt
                self.all_packets_ordered.append(pkt)
                self.stats.increment(pkt.protocol, config.STAT_KEYS)
                if pkt.is_tcp and pkt.protocol != "TCP":
                    self.stats.bump_secondary("TCP")
                self.rate_tracker.record(pkt.timestamp.timestamp())

            query = self.search_var.get()
            for pkt in new_packets:
                if pkt.matches_query(query):
                    tag = pkt.protocol if pkt.protocol in self._tree_tags() else "OTHER"
                    self.tree.insert("", tk.END, values=pkt.as_row(), tags=(tag,))

            self._prune_visible_rows()
            self.tree.yview_moveto(1)

            for key in config.STAT_KEYS:
                self.stat_cards[key].configure(text=str(self.stats.get(key)))
            self.toolbar_count_label.configure(text=f"Packets: {self.stats.get('Total')}")
            self._update_search_status_label()

        self.after(config.UI_FLUSH_INTERVAL_MS, self._flush_capture_queue)

    def _prune_visible_rows(self) -> None:
        """Keep the Treeview widget itself bounded to MAX_VISIBLE_ROWS so it
        stays responsive on long captures. All packets remain in memory
        (self.packets / self.all_packets_ordered) for search and export."""
        children = self.tree.get_children()
        overflow = len(children) - config.MAX_VISIBLE_ROWS
        if overflow > 0:
            for item_id in children[:overflow]:
                self.tree.delete(item_id)

    @staticmethod
    def _tree_tags() -> set[str]:
        return {"TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "SSH", "OTHER"}

    # ------------------------------------------------------------------
    # Mini-IDS alerts
    # ------------------------------------------------------------------
    def _handle_new_alerts(self, new_alerts: list[Alert]) -> None:
        self.alerts.extend(new_alerts)

        self.alerts_text.configure(state="normal")
        if len(self.alerts) == len(new_alerts):
            # first alerts of the session: replace the placeholder text
            self.alerts_text.delete("0.0", tk.END)
        for alert in new_alerts:
            self.alerts_text.insert(tk.END, alert.as_line() + "\n", alert.severity)
        self.alerts_text.see(tk.END)
        self.alerts_text.configure(state="disabled")

        if len(self.alerts) > config.MAX_VISIBLE_ALERTS:
            self.alerts = self.alerts[-config.MAX_VISIBLE_ALERTS:]

        critical = sum(1 for a in self.alerts if a.severity == "critical")
        warning = sum(1 for a in self.alerts if a.severity == "warning")
        if critical:
            self.alert_badge.configure(text=f"🚨 {critical} critical, {warning} warning", text_color="#f38ba8")
        elif warning:
            self.alert_badge.configure(text=f"⚠ {warning} warning", text_color="#f9e2af")

    def clear_alerts(self) -> None:
        self.alerts.clear()
        self.alerts_text.configure(state="normal")
        self.alerts_text.delete("0.0", tk.END)
        self.alerts_text.insert("0.0", "No alerts yet. Start a capture to begin monitoring.")
        self.alerts_text.configure(state="disabled")
        self.alert_badge.configure(text="🛡 No alerts", text_color="#a6e3a1")

    def clear_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.info_text.configure(state="normal")
        self.info_text.delete("0.0", tk.END)
        self.info_text.insert("0.0", "Double-click on a row to see detailed packet analysis.")
        self.info_text.configure(state="disabled")

        self.payload_text.configure(state="normal")
        self.payload_text.delete("0.0", tk.END)
        self.payload_text.insert("0.0", "Select a packet to visualize its payload.")
        self.payload_text.configure(state="disabled")

        self.packets.clear()
        self.all_packets_ordered.clear()
        self._clear_search()
        self.stats.reset(config.STAT_KEYS)
        self.rate_tracker = RateTracker(history_seconds=config.CHART_HISTORY_SECONDS)
        self.clear_alerts()

        for key in config.STAT_KEYS:
            self.stat_cards[key].configure(text="0")

        self.toolbar_count_label.configure(text="Packets: 0")
        self.update_session_stats()

    # ------------------------------------------------------------------
    # Row selection / details
    # ------------------------------------------------------------------
    def on_row_select(self, _event) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        item = self.tree.item(selected[0])
        try:
            num = int(item["values"][0])
        except (ValueError, IndexError):
            return

        pkt = self.packets.get(num)
        if pkt is None:
            return

        self.info_text.configure(state="normal")
        self.info_text.delete("0.0", tk.END)
        self.info_text.insert("0.0", pkt.details)
        self.info_text.configure(state="disabled")

        self.update_payload_view()

    def show_packet_details(self, event) -> None:
        self.on_row_select(event)
        self.details_tab.set("📝 Payload")

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------
    def export_csv(self) -> None:
        if not self.all_packets_ordered:
            show_themed_message(self, "CSV Report", "No packets captured to export.", kind="info")
            return

        filepath = ask_save_file(self, title="CSV Report", initialfile="capture_sniffer.csv",
                                  filetypes=[("CSV file", "*.csv")])
        if not filepath:
            return

        try:
            export_csv(self.all_packets_ordered, filepath)
            show_themed_message(self, "CSV Report", f"Successfully exported to:\n{filepath}", kind="info")
        except Exception as e:
            logger.exception("CSV export failed")
            show_themed_message(self, "Error", str(e), kind="error")

    def export_pcap(self) -> None:
        if not self.all_packets_ordered:
            show_themed_message(self, "PCAP Capture", "No packets captured to export.", kind="info")
            return

        filepath = ask_save_file(self, title="PCAP Capture", initialfile="capture_sniffer.pcap",
                                  filetypes=[("PCAP file", "*.pcap")])
        if not filepath:
            return

        try:
            export_pcap(self.all_packets_ordered, filepath)
            show_themed_message(self, "PCAP Capture", f"Successfully exported to:\n{filepath}", kind="info")
        except Exception as e:
            logger.exception("PCAP export failed")
            show_themed_message(self, "Error", str(e), kind="error")
