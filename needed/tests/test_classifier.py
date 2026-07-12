"""Unit tests for netsniffer.capture.classifier.

All packets are built in memory with scapy - no network access, no root
privileges required.
"""

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Raw

from netsniffer.capture.classifier import classify_packet


def test_classifies_plain_tcp_as_tcp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=22, flags="S")
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "TCP"
    assert result.sport == 51000
    assert result.dport == 22


def test_port_80_reclassified_as_http_when_filter_is_all():
    pkt = IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=51000, dport=80)
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "HTTP"


def test_port_443_reclassified_as_https_when_filter_is_all():
    pkt = IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=51000, dport=443)
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "HTTPS"


def test_tcp_filter_keeps_port_80_tagged_as_tcp():
    """Regression test for the bug where selecting the 'tcp' protocol
    filter still showed port 80/443 traffic as HTTP/HTTPS, making the
    'tcp' filter look broken (almost no rows ever tagged TCP)."""
    pkt = IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=51000, dport=80)
    result = classify_packet(pkt, active_filter="tcp")
    assert result.protocol == "TCP"


def test_tcp_filter_keeps_port_443_tagged_as_tcp():
    pkt = IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=51000, dport=443)
    result = classify_packet(pkt, active_filter="tcp")
    assert result.protocol == "TCP"


def test_classifies_udp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=6000)
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "UDP"


def test_classifies_icmp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "ICMP"
    assert "Type=8" in result.info


def test_classifies_arp():
    pkt = ARP(psrc="10.0.0.1", pdst="10.0.0.2", op=1)
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "ARP"


def test_classifies_dns_query():
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="example.com"))
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "DNS"
    assert "example.com" in result.info


def test_non_ip_non_arp_packet_returns_none():
    from scapy.all import Ether
    pkt = Ether()
    assert classify_packet(pkt, active_filter="All") is None


def test_http_info_extracts_first_line():
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=51000, dport=80)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "HTTP"
    assert result.info == "GET / HTTP/1.1"


# --- SSH banner detection (any port) -------------------------------------------

def test_ssh_banner_detected_on_standard_port():
    pkt = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=22)
        / Raw(load=b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "SSH"
    assert "OpenSSH_9.6" in result.info


def test_ssh_banner_detected_on_nonstandard_port():
    """SSH admin sometimes moves the daemon off port 22 to dodge bots; the
    banner-based detector should still catch it where a port-only
    classifier would just call this 'TCP'."""
    pkt = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=2222)
        / Raw(load=b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "SSH"


def test_ssh_not_confused_with_plain_tcp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=2222, flags="S")
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "TCP"


# --- TLS ClientHello / SNI extraction ------------------------------------------

def _build_client_hello(sni: bytes) -> bytes:
    """Hand-build a minimal, syntactically valid TLS ClientHello record
    carrying a server_name (SNI) extension, for use as a synthetic Raw
    payload in tests."""
    server_name_entry = b"\x00" + len(sni).to_bytes(2, "big") + sni  # name_type=0 (host_name)
    server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    sni_extension = (
        (0x0000).to_bytes(2, "big")  # extension type: server_name
        + len(server_name_list).to_bytes(2, "big")
        + server_name_list
    )
    extensions = sni_extension
    body = (
        b"\x03\x03"  # client_version (TLS 1.2 wire value, ClientHello also used for 1.3)
        + b"\x00" * 32  # random
        + b"\x00"  # session_id_len = 0
        + b"\x00\x02\x13\x01"  # cipher_suites_len=2, one cipher suite
        + b"\x01\x00"  # compression_methods_len=1, null compression
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body  # handshake type 1 = ClientHello
    record = b"\x16" + b"\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


def test_tls_client_hello_sni_extracted_on_standard_port():
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=51000, dport=443)
        / Raw(load=_build_client_hello(b"example.com"))
    )
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "HTTPS"
    assert "example.com" in result.info


def test_tls_client_hello_sni_extracted_on_nonstandard_port():
    """A TLS handshake recognized by its wire format, not by port 443."""
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=51000, dport=8443)
        / Raw(load=_build_client_hello(b"api.example.com"))
    )
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "HTTPS"
    assert "api.example.com" in result.info


def test_plain_https_data_without_clienthello_falls_back_to_generic_message():
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=51000, dport=443)
        / Raw(load=b"\x17\x03\x03\x00\x10" + b"\xaa" * 16)  # application_data record, not a handshake
    )
    result = classify_packet(pkt, active_filter="All")
    assert result.protocol == "HTTPS"
    assert result.info == "Encrypted TLS/SSL traffic"


def test_tcp_filter_suppresses_ssh_and_tls_reclassification():
    ssh_pkt = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=51000, dport=22)
        / Raw(load=b"SSH-2.0-OpenSSH_9.6\r\n")
    )
    assert classify_packet(ssh_pkt, active_filter="tcp").protocol == "TCP"

    tls_pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=51000, dport=443)
        / Raw(load=_build_client_hello(b"example.com"))
    )
    assert classify_packet(tls_pkt, active_filter="tcp").protocol == "TCP"
