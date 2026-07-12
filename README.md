# CodeAlpha-Netsniffer-v3.0
<p align="center">
  <img src="netsniffer/assets/icon.png" width="100" alt="NetSniffer Pro logo">
</p>

<h1 align="center">NetSniffer Pro</h1>

<p align="center">
  A modern network packet sniffer with a CustomTkinter GUI <em>and</em> a terminal CLI,
  built on one shared, GUI-free capture/classification/export core.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/license-MIT-green.svg">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey">
  <img src="https://img.shields.io/badge/engine-Scapy-orange">
</p>

---

## Overview

NetSniffer Pro was built as Task 1 of the CodeAlpha Cybersecurity
Internship. It captures live network traffic, classifies it by protocol,
flags a couple of common suspicious patterns, and exports what it saw for
further analysis — through either a desktop GUI or a terminal CLI, both
running on the exact same underlying engine.

It's a learning/portfolio project rather than a production security tool
— the heuristic alerting (port scans, ARP spoofing) is intentionally
simple, meant to demonstrate the detection logic clearly rather than to
compete with Snort/Suricata.

## Features

- **Live capture** on any interface via scapy's `AsyncSniffer`
- **Protocol classification**: TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS (via TLS SNI), SSH (via banner)
- **Combinable BPF filters** — presets or raw expressions (`tcp and port 443`, `arp or icmp`, ...)
- **Heuristic mini-IDS**: basic port-scan and ARP-spoofing detection
- **Payload inspection**: hex dump, best-effort UTF-8 decode, Shannon entropy
- **CSV & PCAP export**, PCAP readable directly in Wireshark
- **Two frontends, one core** — the GUI and CLI share 100% of the capture/classification/export logic, so neither can drift out of sync with the other
- **No-sudo deployment** — package with PyInstaller and grant `cap_net_raw`/`cap_net_admin` via `setcap` instead of running as root

## Architecture

The project is split into a Tkinter-free **core** (capture, classification,
alerting, analysis, export) and two thin **frontends** that just render
that core's output differently — a CustomTkinter window, or a terminal.
Neither frontend contains any capture/classification logic itself.

```
Frontends            ui/app.py (GUI)   |   cli.py (CLI)
                              \                /
Shared core     capture/  analysis/  export/  models.py  config.py
                              \                /
                              scapy / raw sockets
```

See [full file tree](#) below in the repo, or run `tree netsniffer/` locally.

## Installation

```bash
git clone https://github.com/cybertechsali/netsniffer-pro.git
cd netsniffer-pro
pip install -r requirements.txt
```

## Usage

### GUI

```bash
sudo python3 main.py
```

### CLI

```bash
pip install rich pyfiglet   # optional: colorized banner/output

sudo python3 main_cli.py --list-interfaces
sudo python3 main_cli.py -i eth0
sudo python3 main_cli.py -i eth0 -f "https/tls (port 443)"
sudo python3 main_cli.py -i eth0 -d 30 -o capture.pcap
sudo python3 main_cli.py --about       # full feature list & description
sudo python3 main_cli.py --help        # all options
```

`sudo` is required because scapy opens a raw socket. To avoid it, package
a binary and grant it capabilities directly (see below).

## Running without sudo (packaged binary)

```bash
pyinstaller netsniffer.spec          # or netsniffer_cli.spec for the CLI
sudo ./scripts/setcap_linux.sh dist/netsniffer
dist/netsniffer -i eth0              # no sudo needed after this
```

`setcap` grants only `cap_net_raw`/`cap_net_admin` on the binary file —
strictly narrower than running as root.

## Tests

```bash
pip install pytest
PYTHONPATH=. pytest tests/ -v
```

## Roadmap

- [ ] Read from an existing PCAP file (not just live capture)
- [ ] Savable named BPF filter presets
- [ ] DNS anomaly detection (tunneling, abnormal query volume)
- [ ] Interactive REPL mode for the CLI

## Contributing

PRs welcome. Please keep the core/frontend separation intact — any new
capture, classification, or export logic should stay testable without
Tkinter.

## License

[MIT](LICENSE) © 2026 Ouchahed Salma

## Author

**Ouchahed Salma** — [@cybertechsali](https://github.com/cybertechsali)
