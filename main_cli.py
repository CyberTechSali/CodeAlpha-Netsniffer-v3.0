#!/usr/bin/env python3
"""
CodeAlpha - Cyber Security Internship
Task 1 : Modern Network Sniffer - CLI frontend

Same capture/classification/alert/export core as the GUI (main.py), just a
terminal frontend instead of CustomTkinter — see netsniffer/cli.py.

Run with administrator / root privileges (sudo on Kali Linux) so scapy can
open raw sockets:

    sudo python3 main_cli.py --list-interfaces
    sudo python3 main_cli.py -i eth0
    sudo python3 main_cli.py -i eth0 -f "https/tls (port 443)" -d 30 -o capture.pcap

Requirements:
    pip install scapy
    pip install rich   # optional, for colorized live output
"""

from __future__ import annotations

import sys


def main() -> None:
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        print("[!] Error: the 'scapy' library is required.")
        print("[*] Install it with: pip install scapy")
        sys.exit(1)

    from netsniffer.cli import main as cli_main

    sys.exit(cli_main())


if __name__ == "__main__":
    main()
