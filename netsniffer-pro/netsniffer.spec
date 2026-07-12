# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for NetSniffer Pro.

Build:
    pyinstaller netsniffer.spec

Produces a single-file binary at dist/netsniffer (dist/netsniffer.exe on
Windows). On Linux, follow up the build with `scripts/setcap_linux.sh` to
grant the binary raw-socket capture rights so it no longer needs `sudo`
(see that script for details and the security tradeoffs involved).
"""

import sys

import customtkinter

block_cipher = None

# customtkinter ships its own theme JSON files / assets that must be
# bundled alongside the code, or CTk() raises FileNotFoundError at runtime.
ctk_datas = [(customtkinter.__path__[0], "customtkinter")]

app_datas = ctk_datas + [
    ("netsniffer/assets/icon.png", "assets"),
    ("netsniffer/assets/icon.ico", "assets"),
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=app_datas,
    hiddenimports=[
        "scapy.layers.all",
        "matplotlib.backends.backend_tkagg",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="netsniffer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="netsniffer/assets/icon.ico" if sys.platform.startswith("win") else None,
)
