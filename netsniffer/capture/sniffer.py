"""Threaded packet capture, decoupled from the GUI.

`PacketCapture` wraps `scapy.AsyncSniffer` and pushes fully processed
`CapturedPacket` objects onto a thread-safe `queue.Queue`. The UI polls this
queue on a timer (see `netsniffer.config.UI_FLUSH_INTERVAL_MS`) instead of
scheduling a Tkinter `after()` call per packet.

Why AsyncSniffer instead of a manual thread around `scapy.sniff()`:
`sniff(..., stop_filter=...)` only re-evaluates the stop condition when a
NEW packet arrives. That means calling stop() doesn't actually interrupt
anything until the next matching packet shows up on the wire — on a quiet
interface (or one filtered to a rare protocol) this can look like the
capture "hangs", and any packets that arrive during that dead time get
delivered all at once right when the next packet finally triggers the
check. `AsyncSniffer.stop()` closes the underlying socket directly, so it
interrupts the blocking read immediately instead of waiting for traffic.
"""

from __future__ import annotations

import logging
import queue
from datetime import datetime
from typing import Callable

from scapy.all import AsyncSniffer, Raw

from netsniffer.capture.alerts import AlertEngine
from netsniffer.capture.classifier import build_packet_details, classify_packet
from netsniffer.models import Alert, CapturedPacket

logger = logging.getLogger(__name__)


class PacketCapture:
    """Owns the AsyncSniffer instance and the output queues of
    CapturedPacket / Alert."""

    def __init__(self, on_error: Callable[[Exception], None] | None = None) -> None:
        self._sniffer: AsyncSniffer | None = None
        self._packet_count = 0
        self._on_error = on_error
        self._alert_engine = AlertEngine()
        self.queue: "queue.Queue[CapturedPacket]" = queue.Queue()
        self.alert_queue: "queue.Queue[Alert]" = queue.Queue()

    @property
    def is_running(self) -> bool:
        return self._sniffer is not None and bool(getattr(self._sniffer, "running", False))

    def start(self, iface: str | None, bpf_filter: str | None, active_filter_label: str) -> None:
        if self.is_running:
            logger.warning("start() called while capture is already running; ignoring")
            return

        self._packet_count = 0
        self._alert_engine = AlertEngine()
        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf_filter,
            prn=lambda pkt: self._handle_packet(pkt, active_filter_label),
            store=False,
            promisc=True,
        )

        try:
            self._sniffer.start()
            logger.info("Capture started (iface=%s, filter=%s, label=%s)", iface, bpf_filter, active_filter_label)
        except PermissionError as exc:
            logger.error("Permission error while sniffing: %s", exc)
            self._sniffer = None
            if self._on_error:
                self._on_error(exc)
        except Exception as exc:  # pragma: no cover - defensive, surfaced to UI
            logger.exception("Unexpected error starting capture")
            self._sniffer = None
            if self._on_error:
                self._on_error(exc)

    def stop(self) -> None:
        """Stop the capture immediately (does not wait for the next packet)."""
        if self._sniffer is None:
            return
        try:
            # join=False: don't block the Tkinter main thread while the
            # background thread winds down.
            self._sniffer.stop(join=False)
        except Exception:
            logger.exception("Error while stopping the sniffer")
        finally:
            logger.info("Capture stop requested")
            self._sniffer = None

    def poll_error(self) -> Exception | None:
        """Return any exception raised inside the sniffer thread after the
        fact (e.g. interface disappeared mid-capture)."""
        if self._sniffer is None:
            return None
        return getattr(self._sniffer, "exception", None)

    def _handle_packet(self, packet, active_filter_label: str) -> None:
        for alert in self._alert_engine.feed(packet):
            self.alert_queue.put(alert)
            logger.warning("[%s] %s", alert.category, alert.message)

        result = classify_packet(packet, active_filter=active_filter_label)
        if result is None:
            return

        self._packet_count += 1
        num = self._packet_count
        timestamp = datetime.now()
        details = build_packet_details(packet, num, timestamp.strftime("%H:%M:%S"), result)
        raw_payload = packet[Raw].load if packet.haslayer(Raw) else b""

        captured = CapturedPacket(
            num=num,
            timestamp=timestamp,
            src=result.src,
            dst=result.dst,
            protocol=result.protocol,
            sport=result.sport,
            dport=result.dport,
            info=result.info,
            details=details,
            raw_payload=raw_payload,
            raw_scapy_packet=packet,
            is_tcp=result.is_tcp,
        )
        self.queue.put(captured)

    def drain(self, max_items: int | None = None) -> list[CapturedPacket]:
        """Pop everything currently queued (non-blocking), for UI batching."""
        items: list[CapturedPacket] = []
        while max_items is None or len(items) < max_items:
            try:
                items.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return items

    def drain_alerts(self, max_items: int | None = None) -> list[Alert]:
        """Pop every pending mini-IDS alert (non-blocking), for UI batching."""
        items: list[Alert] = []
        while max_items is None or len(items) < max_items:
            try:
                items.append(self.alert_queue.get_nowait())
            except queue.Empty:
                break
        return items
