"""Unit tests for netsniffer.capture.alerts.

Uses a fake, manually-advanced clock so the time-window logic (port scan
window, alert cooldowns) is fully deterministic - no real sleeps, no
flakiness.
"""

from scapy.all import ARP, IP, TCP, UDP

from netsniffer import config
from netsniffer.capture.alerts import AlertEngine


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _tcp_packet(src: str, dport: int) -> object:
    return IP(src=src, dst="10.0.0.99") / TCP(sport=51000, dport=dport, flags="S")


def _arp_reply(psrc: str, hwsrc: str) -> object:
    return ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst="10.0.0.99")


# --- Port scan detection --------------------------------------------------------

def test_no_alert_below_threshold():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    for port in range(1, config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD - 1):
        alerts = engine.feed(_tcp_packet("10.0.0.5", port))
        assert alerts == []


def test_alert_fires_once_threshold_reached():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    for port in range(1, config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD + 5):
        fired += engine.feed(_tcp_packet("10.0.0.5", port))

    assert len(fired) == 1
    assert fired[0].category == "PORT_SCAN"
    assert fired[0].actor == "10.0.0.5"


def test_normal_traffic_to_few_ports_does_not_alert():
    """A normal client hitting the same 2-3 ports repeatedly (e.g. HTTP
    keep-alive) must never be flagged, even with many packets."""
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    for _ in range(200):
        fired += engine.feed(_tcp_packet("10.0.0.5", 443))
        clock.advance(0.01)
    assert fired == []


def test_ports_outside_time_window_do_not_count_together():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    # Half the distinct ports now...
    for port in range(1, config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD // 2):
        fired += engine.feed(_tcp_packet("10.0.0.5", port))
    # ...then jump forward well past the window before sending the rest.
    clock.advance(config.PORT_SCAN_WINDOW_SECONDS + 1)
    for port in range(1000, 1000 + config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD // 2):
        fired += engine.feed(_tcp_packet("10.0.0.5", port))
    assert fired == []  # never enough *simultaneously present* distinct ports


def test_cooldown_prevents_alert_flooding():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    for port in range(1, config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD + 20):
        fired += engine.feed(_tcp_packet("10.0.0.5", port))
    assert len(fired) == 1  # not one alert per extra port touched


def test_udp_port_scan_also_detected():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    for port in range(1, config.PORT_SCAN_DISTINCT_PORTS_THRESHOLD + 1):
        pkt = IP(src="10.0.0.5", dst="10.0.0.99") / UDP(sport=51000, dport=port)
        fired += engine.feed(pkt)
    assert len(fired) == 1
    assert fired[0].category == "PORT_SCAN"


# --- ARP spoofing detection ------------------------------------------------------

def test_no_alert_for_single_consistent_mac():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    for _ in range(5):
        fired += engine.feed(_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:01"))
    assert fired == []


def test_alert_when_ip_claimed_by_second_mac():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    fired += engine.feed(_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:01"))
    fired += engine.feed(_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:02"))
    assert len(fired) == 1
    assert fired[0].category == "ARP_SPOOF"
    assert fired[0].severity == "critical"
    assert fired[0].actor == "10.0.0.1"


def test_arp_reply_cooldown_prevents_flooding():
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    fired += engine.feed(_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:01"))
    for _ in range(10):
        fired += engine.feed(_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:02"))
    assert len(fired) == 1


def test_arp_who_has_requests_do_not_trigger_spoof_check():
    """op=1 ('who-has') is a question, not a claim of ownership - it must
    never be treated as evidence of IP/MAC binding."""
    clock = FakeClock()
    engine = AlertEngine(clock=clock)
    fired = []
    fired += engine.feed(ARP(op=1, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01", pdst="10.0.0.99"))
    fired += engine.feed(ARP(op=1, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:02", pdst="10.0.0.99"))
    assert fired == []
