from netsniffer.analysis.payload import (
    compute_entropy,
    decode_utf8_best_effort,
    get_hex_dump,
    get_payload_analysis,
    guess_payload_nature,
)


def test_empty_payload_messages():
    assert decode_utf8_best_effort(b"") == "No payload"
    assert get_hex_dump(b"") == "No payload data"
    assert get_payload_analysis(b"") == "No payload data"


def test_decode_utf8_best_effort():
    assert decode_utf8_best_effort(b"hello") == "hello"


def test_hex_dump_format():
    dump = get_hex_dump(b"AB")
    assert "0000" in dump
    assert "41 42" in dump
    assert "|AB" in dump


def test_entropy_of_uniform_bytes_is_zero():
    assert compute_entropy(b"AAAAAAAA") == 0.0


def test_entropy_of_random_looking_bytes_is_high():
    payload = bytes(range(256))
    assert compute_entropy(payload) > 7.5


def test_guess_payload_nature_plain_text():
    assert guess_payload_nature(printable_ratio=95, entropy=4.0) == "Plain text / Cleartext"


def test_guess_payload_nature_encrypted():
    assert guess_payload_nature(printable_ratio=50, entropy=7.9) == "Encrypted or Compressed data (TLS/SSH/ZIP)"


def test_guess_payload_nature_structured_binary():
    assert guess_payload_nature(printable_ratio=5, entropy=1.0) == "Structured binary headers / Null-padded data"
