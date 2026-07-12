"""Pure payload inspection helpers (hex dump, entropy analysis).

No Tkinter dependency, so these are trivial to unit test on raw bytes.
"""

from __future__ import annotations

import math


def decode_utf8_best_effort(payload: bytes) -> str:
    if not payload:
        return "No payload"
    try:
        return payload.decode("utf-8", errors="replace")
    except Exception:
        return str(payload)


def get_hex_dump(payload: bytes) -> str:
    if not payload:
        return "No payload data"
    lines = []
    for i in range(0, len(payload), 16):
        chunk = payload[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def compute_entropy(payload: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not payload:
        return 0.0
    size = len(payload)
    counts: dict[int, int] = {}
    for b in payload:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / size
        entropy -= p * math.log2(p)
    return entropy


def guess_payload_nature(printable_ratio: float, entropy: float) -> str:
    if printable_ratio > 85:
        return "Plain text / Cleartext"
    if entropy > 7.2:
        return "Encrypted or Compressed data (TLS/SSH/ZIP)"
    if printable_ratio < 10 and entropy < 3.0:
        return "Structured binary headers / Null-padded data"
    return "Binary data"


def get_payload_analysis(payload: bytes) -> str:
    if not payload:
        return "No payload data"

    size = len(payload)
    printable_count = sum(1 for b in payload if 32 <= b < 127 or b in (9, 10, 13))
    ratio = (printable_count / size) * 100
    entropy = compute_entropy(payload)
    nature = guess_payload_nature(ratio, entropy)

    return (
        "=== PAYLOAD STATISTICAL ANALYSIS ===\n\n"
        f" Payload Size                : {size} bytes\n"
        f" Printable Character Ratio   : {ratio:.2f} %\n"
        f" Entropy (Randomness)        : {entropy:.4f} (maximum 8.0)\n\n"
        f" [!] Suspected Nature        : {nature}\n"
    )
