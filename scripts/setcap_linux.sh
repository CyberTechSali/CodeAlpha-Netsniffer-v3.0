#!/usr/bin/env bash
# Grant a compiled NetSniffer Pro binary the two Linux capabilities it
# actually needs to capture traffic, instead of running the whole GUI as
# root via `sudo python3 main.py`:
#
#   cap_net_raw   - open AF_PACKET raw sockets (scapy's sniff/AsyncSniffer)
#   cap_net_admin - flip the NIC into promiscuous mode (promisc=True in
#                   netsniffer/capture/sniffer.py)
#
# Usage:
#   sudo ./scripts/setcap_linux.sh dist/netsniffer
#
# Notes / tradeoffs:
# - setcap must be run once, as root, by whoever packages/installs the
#   binary. After that, any user on the machine can run the binary itself
#   without sudo -- the kernel grants those two capabilities to the
#   process at exec time based on the file's extended attributes.
# - This only works reliably for the --onefile PyInstaller build produced
#   by netsniffer.spec, where the same on-disk binary re-execs itself to
#   do the real work. If you switch to a --onedir build, setcap the real
#   binary inside dist/netsniffer/, not a wrapper script.
# - setcap capabilities are lost if the binary is later modified in place
#   (e.g. re-run PyInstaller) or copied with a tool that doesn't preserve
#   extended attributes (some `cp`/archive/CI pipelines strip them) --
#   re-run this script after any rebuild or a plain filesystem copy.
# - This is strictly narrower than sudo: cap_net_raw/cap_net_admin let the
#   process touch network interfaces, nothing else. It still can't read
#   arbitrary files as root, write system config, etc.

set -euo pipefail

BIN="${1:-dist/netsniffer}"

if [[ ! -f "$BIN" ]]; then
    echo "[!] Binary not found: $BIN" >&2
    echo "    Build it first with: pyinstaller netsniffer.spec" >&2
    exit 1
fi

if ! command -v setcap >/dev/null 2>&1; then
    echo "[!] 'setcap' not found. Install it first:" >&2
    echo "      Debian/Ubuntu/Kali: sudo apt install libcap2-bin" >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[!] This needs root once, to set the capability on the file." >&2
    echo "    Re-run as: sudo $0 $BIN" >&2
    exit 1
fi

setcap 'cap_net_raw,cap_net_admin+eip' "$BIN"

echo "[+] Capabilities set on $BIN:"
getcap "$BIN"
echo "[+] Any user can now run it without sudo: $BIN"
