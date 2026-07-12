# CodeAlpha-Netsniffer-v3.0
netsniffer-pro/
├── main.py                    # GUI entry point
├── main_cli.py                 # CLI entry point
├── netsniffer.spec              # PyInstaller build config (GUI)
├── netsniffer_cli.spec          # PyInstaller build config (CLI)
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
│
├── netsniffer/
│   ├── config.py               # centralized constants (colors, filters, app metadata)
│   ├── models.py                # shared dataclasses
│   ├── cli.py                   # CLI frontend
│   ├── assets.py                # asset path resolution (dev + frozen binary)
│   ├── assets/                  # icon.png / icon.ico
│   │
│   ├── capture/
│   │   ├── sniffer.py           # PacketCapture
│   │   ├── classifier.py        # protocol classification
│   │   └── alerts.py            # heuristic mini-IDS
│   │
│   ├── analysis/
│   │   ├── payload.py           # hex dump / entropy / UTF-8
│   │   └── traffic_rate.py      # packets/sec tracker
│   │
│   ├── export/
│   │   └── exporters.py         # CSV / PCAP export
│   │
│   └── ui/                      # GUI frontend (only Tkinter-dependent part)
│       ├── app.py
│       └── save_dialog.py
│
├── scripts/
│   ├── build_linux.sh           # PyInstaller build + setcap
│   └── setcap_linux.sh          # grant raw-socket capability, no sudo needed
│
└── tests/
    ├── test_classifier.py
    ├── test_alerts.py
    ├── test_payload.py
    └── test_traffic_rate.py
