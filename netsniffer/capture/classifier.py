"""Pure protocol classification for sniffed packets.

Deliberately has ZERO dependency on Tkinter, threading, or the GUI. It only
depends on scapy's packet objects. This is what makes it possible to write
fast unit tests that build synthetic packets in memory and assert on the
classification result, without ever opening a socket or needing root
privileges.
"""

from __future__ import annotations

import struct

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Packet, Raw

from netsniffer.models import ClassificationResult


def peek_http_first_line(packet: Packet) -> str:
    """Best-effort extraction of the first line of an HTTP request/response."""
    if not packet.haslayer(Raw):
        return ""
    try:
        data = packet[Raw].load.decode("utf-8", errors="replace")
    except Exception:
        return ""
    first_line = data.split("\r\n", 1)[0].strip()
    return first_line[:80] if first_line else ""


# --- SSH banner detection -----------------------------------------------------
#
# The SSH protocol identification exchange (RFC 4253 4.2) always starts with
# a plaintext line "SSH-<protoversion>-<softwareversion> ...\r\n", sent by
# either side *before* encryption kicks in. Because this line is plaintext
# regardless of which TCP port is used, matching on it (instead of on
# port == 22) lets us recognize SSH running on a non-standard port, which a
# pure port-number classifier can never do.
_SSH_BANNER_PREFIX = b"SSH-"


def peek_ssh_banner(packet: Packet) -> str:
    """Return the decoded SSH identification banner if this packet is one,
    else an empty string."""
    if not packet.haslayer(Raw):
        return ""
    load = packet[Raw].load
    if not load.startswith(_SSH_BANNER_PREFIX):
        return ""
    try:
        text = load.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    except Exception:
        return ""
    return text[:80]


# --- TLS ClientHello SNI extraction --------------------------------------------
#
# We don't decrypt anything (impossible without keys) - we only parse the
# *unencrypted* TLS handshake header that precedes encryption: the
# ClientHello record. Real browsers/clients put the target hostname in the
# "server_name" extension (SNI) in plaintext so middleboxes can route the
# connection, which is exactly what lets us show e.g.
# "TLS ClientHello -> example.com" instead of just "Encrypted traffic".
#
# Wire format (simplified, big-endian):
#   TLS record header:      ContentType(1) Version(2) Length(2)
#   Handshake header:       HandshakeType(1) Length(3)
#   ClientHello body:       Version(2) Random(32) SessionIDLen(1) SessionID(*)
#                           CipherSuitesLen(2) CipherSuites(*)
#                           CompressionMethodsLen(1) CompressionMethods(*)
#                           ExtensionsLen(2) Extensions(*)
#   Extension:               Type(2) Length(2) Data(*)
#   server_name extension:   ServerNameListLen(2) NameType(1) NameLen(2) Name(*)
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
_TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
_TLS_EXTENSION_SERVER_NAME = 0x0000


def peek_tls_client_hello_sni(payload: bytes) -> str | None:
    """Return the SNI hostname from a TLS ClientHello, or None if `payload`
    isn't a (plaintext) TLS ClientHello record. Malformed/truncated input is
    treated as "not a ClientHello" rather than raised."""
    try:
        if len(payload) < 6:
            return None
        content_type, _version, record_len = struct.unpack(">BHH", payload[:5])
        if content_type != _TLS_CONTENT_TYPE_HANDSHAKE:
            return None

        handshake = payload[5:5 + record_len]
        if len(handshake) < 4:
            return None
        handshake_type = handshake[0]
        if handshake_type != _TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return None

        pos = 4  # skip handshake type(1) + length(3)
        pos += 2 + 32  # client version(2) + random(32)

        session_id_len = handshake[pos]
        pos += 1 + session_id_len

        cipher_suites_len = struct.unpack(">H", handshake[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len

        compression_len = handshake[pos]
        pos += 1 + compression_len

        if pos + 2 > len(handshake):
            return None  # no extensions present
        extensions_len = struct.unpack(">H", handshake[pos:pos + 2])[0]
        pos += 2
        extensions_end = pos + extensions_len

        while pos + 4 <= extensions_end and pos + 4 <= len(handshake):
            ext_type, ext_len = struct.unpack(">HH", handshake[pos:pos + 4])
            ext_data = handshake[pos + 4:pos + 4 + ext_len]
            if ext_type == _TLS_EXTENSION_SERVER_NAME and len(ext_data) >= 5:
                # server_name_list_len(2) name_type(1) name_len(2) name(*)
                name_len = struct.unpack(">H", ext_data[3:5])[0]
                hostname = ext_data[5:5 + name_len]
                return hostname.decode("ascii", errors="replace")
            pos += 4 + ext_len
        return None
    except (struct.error, IndexError):
        return None


def classify_packet(packet: Packet, active_filter: str = "All") -> ClassificationResult | None:
    """Classify a single sniffed packet into a protocol + display fields.

    `active_filter` is the friendly filter label currently selected by the
    user (see `netsniffer.config.FILTER_MAP`), e.g. "All", "tcp", "udp".

    Important behavior: when `active_filter == "tcp"`, every TCP packet is
    kept tagged as "TCP", even if it's on port 80/443. Previously, TCP
    packets on those ports were always reclassified as HTTP/HTTPS, which
    meant that selecting the "tcp" filter captured traffic correctly but
    almost none of it displayed as "TCP" (most real traffic is HTTPS on
    port 443), making the filter look broken. Any other filter (including
    "All") keeps the original HTTP/HTTPS sub-classification.
    """
    # ARP has no IP layer, handle it first.
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            info = f"who-has {arp.pdst} ? Tell {arp.psrc}"
        elif arp.op == 2:
            info = f"{arp.psrc} is-at {arp.hwsrc}"
        else:
            info = str(arp.op)
        return ClassificationResult(protocol="ARP", src=arp.psrc, dst=arp.pdst, info=info)

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src, dst = ip_layer.src, ip_layer.dst

    if packet.haslayer(DNS):
        dns = packet[DNS]
        sport = packet[UDP].sport if packet.haslayer(UDP) else ""
        dport = packet[UDP].dport if packet.haslayer(UDP) else ""
        if dns.qd is not None:
            qname = dns.qd.qname
            qname = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
            info = f"{'Response' if dns.qr == 1 else 'Query'}: {qname}"
        else:
            info = "Response" if dns.qr == 1 else "Query"
        return ClassificationResult(protocol="DNS", src=src, dst=dst, sport=sport, dport=dport, info=info)

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        sport, dport = tcp_layer.sport, tcp_layer.dport
        only_plain_tcp = active_filter == "tcp"

        # SSH is recognized by its plaintext identification banner, not by
        # port 22, so it's correctly flagged even on a non-standard port.
        ssh_banner = "" if only_plain_tcp else peek_ssh_banner(packet)

        # A TLS ClientHello is recognized by its record/handshake header,
        # not by port 443, so a TLS handshake on a non-standard port is
        # still surfaced with its SNI hostname instead of looking like
        # opaque TCP.
        sni = None
        if not only_plain_tcp and packet.haslayer(Raw):
            sni = peek_tls_client_hello_sni(bytes(packet[Raw].load))

        if ssh_banner:
            protocol = "SSH"
            info = ssh_banner
        elif sni is not None:
            protocol = "HTTPS"
            info = f"TLS ClientHello -> SNI: {sni}" if sni else "TLS ClientHello (no SNI)"
        elif not only_plain_tcp and (sport == 80 or dport == 80):
            protocol = "HTTP"
            info = peek_http_first_line(packet)
        elif not only_plain_tcp and (sport == 443 or dport == 443):
            protocol = "HTTPS"
            info = "Encrypted TLS/SSL traffic"
        else:
            protocol = "TCP"
            info = f"Flags={tcp_layer.flags}"
        return ClassificationResult(protocol=protocol, src=src, dst=dst, sport=sport, dport=dport, info=info, is_tcp=True)

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        return ClassificationResult(
            protocol="UDP", src=src, dst=dst,
            sport=udp_layer.sport, dport=udp_layer.dport,
            info=f"Len={udp_layer.len}",
        )

    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        return ClassificationResult(
            protocol="ICMP", src=src, dst=dst,
            info=f"Type={icmp_layer.type} Code={icmp_layer.code}",
        )

    return ClassificationResult(protocol="OTHER", src=src, dst=dst)


def build_packet_details(packet: Packet, num: int, timestamp_str: str, result: ClassificationResult) -> str:
    """Build the multi-line human-readable details block for the Info tab."""
    details = (
        f"=== PACKET #{num} INFO ===\n"
        f"Capture time     : {timestamp_str}\n"
        f"Total length     : {len(packet)} bytes\n\n"
        f"[ PROTOCOL: {result.protocol} ]\n"
        f"  Source         : {result.src}\n"
        f"  Destination    : {result.dst}\n"
    )
    if result.sport:
        details += f"  Source Port    : {result.sport}\n  Dest Port      : {result.dport}\n"

    if result.protocol == "TCP" and packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        details += (
            f"  Seq Number     : {tcp_layer.seq}\n"
            f"  Ack Number     : {tcp_layer.ack}\n"
            f"  Flags          : {tcp_layer.flags}\n"
        )
    elif result.protocol == "DNS" and packet.haslayer(DNS):
        dns = packet[DNS]
        details += f"  Transaction ID : {dns.id}\n  {result.info}\n"
    elif result.protocol == "HTTP":
        details += f"  {result.info}\n" if result.info else "  (No readable HTTP headers in this packet)\n"
    elif result.protocol == "HTTPS":
        if result.info.startswith("TLS ClientHello"):
            details += f"  {result.info}\n  (Rest of the handshake and application data are encrypted.)\n"
        else:
            details += "  Payload is TLS-encrypted, contents not readable.\n"
    elif result.protocol == "SSH":
        details += f"  Identification string: {result.info}\n  (Session is encrypted immediately after key exchange.)\n"
    elif result.protocol == "ARP":
        details += f"  {result.info}\n"
    elif result.protocol == "ICMP" and packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        details += f"  Type           : {icmp_layer.type}\n  Code           : {icmp_layer.code}\n"
    elif result.protocol == "UDP" and packet.haslayer(UDP):
        details += f"  UDP Length     : {packet[UDP].len}\n"
    else:
        details += "  Non-standard protocol, not decoded.\n"

    return details
