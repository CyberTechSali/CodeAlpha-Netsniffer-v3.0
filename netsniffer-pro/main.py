#!/usr/bin/env python3
"""
CodeAlpha - Cyber Security Internship
Task 1 : Modern Network Sniffer - CustomTkinter GUI

Entry point. Run with administrator / root privileges (sudo on Kali Linux)
so scapy can open raw sockets:

    sudo python3 main.py

Requirements:
    pip install scapy customtkinter
"""

from __future__ import annotations

import sys

from netsniffer.logging_setup import configure_logging


def main() -> None:
    configure_logging()

    try:
        import customtkinter  # noqa: F401
    except ImportError:
        print("[!] Error: the 'customtkinter' library is required.")
        print("[*] Install it with: pip install customtkinter")
        sys.exit(1)

    try:
        import scapy.all  # noqa: F401
    except ImportError:
        print("[!] Error: the 'scapy' library is required.")
        print("[*] Install it with: pip install scapy")
        sys.exit(1)

    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("[!] Error: the 'matplotlib' library is required (used by the Charts tab).")
        print("[*] Install it with: pip install matplotlib")
        sys.exit(1)

    from netsniffer.ui.app import ModernNetworkSnifferGUI

    app = ModernNetworkSnifferGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
