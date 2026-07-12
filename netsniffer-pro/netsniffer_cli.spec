# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the NetSniffer Pro CLI (netsniffer/cli.py).

Build:
    pyinstaller netsniffer_cli.spec

Produces a single-file binary at dist/netsniffer-cli. Same setcap workflow
as the GUI binary applies -- see scripts/setcap_linux.sh -- to run it
without sudo:

    pyinstaller netsniffer_cli.spec
    sudo ./scripts/setcap_linux.sh dist/netsniffer-cli
"""

block_cipher = None

a = Analysis(
    ["main_cli.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "scapy.layers.all",
        "rich",
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
    name="netsniffer-cli",
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
)
