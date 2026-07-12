#!/usr/bin/env bash
# Build the NetSniffer Pro one-file Linux binary and grant it the raw-socket
# capabilities it needs, so end users never have to run it with `sudo`.
#
# Usage:
#   ./scripts/build_linux.sh
#
# This script itself needs sudo (to call setcap on the freshly built
# binary) -- that's a one-time packaging step done by whoever builds/ships
# the binary, not something every user has to do every time they run it.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "[*] Building with PyInstaller..."
pyinstaller netsniffer.spec --noconfirm

BIN="dist/netsniffer"
if [[ ! -f "$BIN" ]]; then
    echo "[!] Build failed: $BIN not found." >&2
    exit 1
fi

echo "[*] Granting raw-socket capabilities to $BIN"
./scripts/setcap_linux.sh "$BIN"

echo "[+] Done. Run it directly, no sudo needed:"
echo "      $BIN"
