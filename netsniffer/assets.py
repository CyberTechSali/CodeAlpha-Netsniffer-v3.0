"""Resource path resolution for bundled assets (icons, etc.).

When running from source, assets live alongside this package on disk.
When running as a PyInstaller-frozen binary (see `netsniffer.spec`), the
same files are unpacked at runtime into a temporary directory exposed as
`sys._MEIPASS`. This module hides that difference behind one function so
the rest of the codebase never has to check `sys.frozen` itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent


def resource_path(*parts: str) -> Path:
    """Return the absolute path to a bundled resource.

    Example: resource_path("assets", "icon.png")
    """
    base = Path(getattr(sys, "_MEIPASS", _PACKAGE_DIR))
    # When frozen, PyInstaller (per netsniffer.spec) places the assets
    # directory at the root of the bundle rather than nested under
    # netsniffer/, so try both locations.
    candidate = base / Path(*parts)
    if candidate.exists():
        return candidate
    return _PACKAGE_DIR / Path(*parts)


def icon_png_path() -> Path:
    return resource_path("assets", "icon.png")


def icon_ico_path() -> Path:
    return resource_path("assets", "icon.ico")
