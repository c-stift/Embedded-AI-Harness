"""Host tier for FR-040 (DNS query over the radio), the FR-039 station-mode target
rule and the FR-014 no-redirect relay. Pure logic only — no sockets, no files."""
import struct

import pytest

import dns_probe as dns
import netscan_controller as ns
import wifi_controller as wc


# ── FR-040 query encoding ────────────────────────────────────────────────

def test_fr040_builds_a_recursive_a_query():
    txid, pkt = dns.build_query("example.com", "A", txid=0x1234)
    assert txid == 0x1234
    assert pkt[:12] == struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    assert pkt[12:] == b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)


@pytest.mark.parametrize("name", ["", "   ", "a" * 64 + ".com", ".".join(["a" * 60] * 5), "a..b"])
def test_fr040_rejects_bad_names(name):
    with pytest.raises(ValueError):
        dns.build_query(name)


def test_fr040_rejects_unknown_type():
    with pytest.raises(ValueError):
        dns.build_query("example.com", "MX")


# ── FR-040 reply parsing ─────────────────────────────────────────────────

def _reply(txid, flags=0x8180, answers=((0xC00C, 1, 60, b"\xc0\xa8\x04\x01"),)):
    q = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    msg = struct.pack(">HHHHHH", txid, flags, 1, len(answers), 0, 0) + q
    for ptr, rtype, ttl, rdata in answers:
        msg += struct.pack(">HHHIH", ptr, rtype, 1, ttl, len(rdata)) + rdata
    return msg


def test_fr040_parses_a_compressed_a_answer():
    r = dns.parse_response(_reply(7), 7)
    assert r["rcode"] == "NOERROR"
    assert r["answers"] == [{"name": "example.com", "type": "A", "ttl": 60, "data": "192.168.4.1"}]


def test_fr040_reports_nxdomain():
    r = dns.parse_response(_reply(7, flags=0x8183, answers=()), 7)
    assert r["rcode"] == "NXDOMAIN" and r["answers"] == []


@pytest.mark.parametrize("msg,txid", [(_reply(8), 7), (_reply(7, flags=0x0100), 7), (b"\x00" * 5, 7)])
def test_fr040_rejects_foreign_or_broken_replies(msg, txid):
    with pytest.raises(ValueError):
        dns.parse_response(msg, txid)


def test_fr040_rejects_a_truncated_answer():
    with pytest.raises(ValueError):
        dns.parse_response(_reply(7)[:-2], 7)


@pytest.mark.parametrize("t,ok", [(None, True), (3, True), (0.5, True), (10, True), (0.1, False), (11, False),
                                  ("x", False)])
def test_fr040_clamps_timeout(t, ok):
    if ok:
        assert dns.MIN_TIMEOUT_S <= dns.clamp_timeout(t) <= dns.MAX_TIMEOUT_S
    else:
        with pytest.raises(ValueError):
            dns.clamp_timeout(t)


# ── FR-039 station mode ──────────────────────────────────────────────────

STA = {"active": True, "ip": "192.168.4.2", "gateway": "192.168.4.1"}


@pytest.mark.parametrize("host,ok", [("192.168.4.1", True), ("192.168.4.2", False), ("192.168.4.3", False),
                                     ("192.168.0.10", False), ("192.168.4.0/24", False), ("example.com", False)])
def test_fr039_station_mode_accepts_only_the_joined_ap(host, ok):
    if ok:
        assert ns.select_target(host, STA, "192.168.4.0/24", "192.168.4.1") == host
    else:
        with pytest.raises(ValueError):
            ns.select_target(host, STA, "192.168.4.0/24", "192.168.4.1")


def test_fr039_station_mode_without_gateway_refuses():
    with pytest.raises(ValueError):
        ns.select_target("192.168.4.1", {"active": True, "ip": "192.168.4.2", "gateway": ""},
                         "192.168.4.0/24", "192.168.4.1")


def test_fr039_ap_mode_rules_unchanged():
    off = {"active": False, "ip": "", "gateway": ""}
    assert ns.select_target("192.168.4.15", off, "192.168.4.0/24", "192.168.4.1") == "192.168.4.15"
    with pytest.raises(ValueError):
        ns.select_target("192.168.4.1", off, "192.168.4.0/24", "192.168.4.1")


# ── FR-014 redirects ─────────────────────────────────────────────────────

def test_fr014_no_redirect_handler_declines_every_redirect():
    # Returning None makes urllib raise HTTPError for the 3xx, which http_relay hands back as status + headers.
    h = wc._NoRedirect()
    for code in (301, 302, 303, 307, 308):
        assert h.redirect_request(None, None, code, "x", {"Location": "/x"}, "http://d/x") is None


def test_fr014_relay_defaults_to_following():
    import inspect
    assert inspect.signature(wc.http_relay).parameters["follow_redirects"].default is True


@pytest.mark.parametrize("value,want", [("tcp", "tcp"), ("udp", "udp"), (None, "tcp")])
def test_fr039_parses_protocol(value, want):
    assert ns.parse_protocol(value) == want


@pytest.mark.parametrize("value", ["icmp", "TCP", "", 1])
def test_fr039_rejects_unknown_protocol(value):
    with pytest.raises(ValueError):
        ns.parse_protocol(value)
