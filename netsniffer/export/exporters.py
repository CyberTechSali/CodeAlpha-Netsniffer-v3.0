"""Export captured packets to CSV or PCAP."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from scapy.all import wrpcap

from netsniffer.models import CapturedPacket

logger = logging.getLogger(__name__)

CSV_HEADER = ["No.", "Time", "Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port", "Info"]


def export_csv(packets: list[CapturedPacket], filepath: str | Path) -> None:
    logger.info("Exporting %d packets to CSV: %s", len(packets), filepath)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        writer.writerows(pkt.as_row() for pkt in packets)


def export_pcap(packets: list[CapturedPacket], filepath: str | Path) -> None:
    raw_packets = [pkt.raw_scapy_packet for pkt in packets if pkt.raw_scapy_packet is not None]
    logger.info("Exporting %d raw packets to PCAP: %s", len(raw_packets), filepath)
    wrpcap(str(filepath), raw_packets)
