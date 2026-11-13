"""
DNS Probe — one DNS query over UDP from the bench radio to a device on the
WiFi side (FR-040).

Verifies a DUT's DNS server (a captive portal answering every name with its
own address) — an observation the HTTP relay cannot make, because the relay
resolves names on the Pi, through eth0, and never asks the DUT.

The pure core builds the query and parses the answer; `query` sends one
datagram and waits for one reply. Which servers may be asked is decided by the
portal (composition root), which knows the radio's state.
"""

import random
import socket
import struct
import time

TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "TXT": 16, "ANY": 255}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
MIN_TIMEOUT_S = 0.5
MAX_TIMEOUT_S = 10.0
DEFAULT_TIMEOUT_S = 3.0

# ---------------------------------------------------------------------------
# Pure core
# ---------------------------------------------------------------------------


def encode_name(name: str) -> bytes:
    """`example.com` -> length-prefixed labels; raises ValueError on a bad name."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    name = name.strip().rstrip(".")
    out = b""
    for label in name.split("."):
        raw = label.encode("idna") if label else b""
        if not 1 <= len(raw) <= 63:
            raise ValueError(f"bad label {label!r} in {name!r}")
        out += bytes([len(raw)]) + raw
    if len(out) + 1 > 255:
        raise ValueError("name longer than 255 bytes")
    return out + b"\x00"


def build_query(name: str, qtype: str = "A", txid: int = None) -> tuple:
    """Return (txid, packet) for one recursive query of `qtype`."""
    if qtype not in TYPES:
        raise ValueError(f"type must be one of {sorted(TYPES)}")
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, one question
    return txid, header + encode_name(name) + struct.pack(">HH", TYPES[qtype], 1)


def _read_name(msg: bytes, off: int, depth: int = 0) -> tuple:
    """Decode a (possibly compressed) name at `off`; return (name, next_offset)."""
    if depth > 10:
        raise ValueError("name compression loop")
    labels = []
    while True:
        if off >= len(msg):
            raise ValueError("name runs past the message")
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            name, _ = _read_name(msg, ptr, depth + 1)
            labels.append(name)
            return ".".join(x for x in labels if x), off + 2
        off += 1
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n


def parse_response(msg: bytes, txid: int) -> dict:
    """Parse a reply to `txid`: rcode, flags and the answer records."""
    if len(msg) < 12:
        raise ValueError("reply shorter than a DNS header")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != txid:
        raise ValueError(f"reply id {rid} does not match query id {txid}")
    if not flags & 0x8000:
        raise ValueError("not a response (QR bit clear)")
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise ValueError("truncated answer record")
        rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if len(rdata) != rdlen:
            raise ValueError("truncated answer data")
        if rtype == 1 and rdlen == 4:
            data = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlen == 16:
            data = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            data, _ = _read_name(msg, off)
        else:
            data = rdata.hex()
        answers.append({"name": name, "type": TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl, "data": data})
        off += rdlen
    return {"rcode": RCODES.get(flags & 0x000F, str(flags & 0x000F)), "authoritative": bool(flags & 0x0400),
            "answers": answers}


def clamp_timeout(value) -> float:
    if value is None:
        return DEFAULT_TIMEOUT_S
    try:
        t = float(value)
    except (TypeError, ValueError):
        raise ValueError("timeout_s must be a number") from None
    if not (MIN_TIMEOUT_S <= t <= MAX_TIMEOUT_S):
        raise ValueError(f"timeout_s must be {MIN_TIMEOUT_S:g}-{MAX_TIMEOUT_S:g}")
    return t

# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


def query(server: str, name: str, qtype: str, source_ip: str, timeout_s: float) -> dict:
    """Send one query from `source_ip` (the radio's address) to `server`:53 and parse the reply.

    No reply within the budget is an answer too — `ok` stays true with `timeout: true`, because a DUT that
    runs no DNS server is exactly what some tests need to observe."""
    txid, packet = build_query(name, qtype)
    start = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((source_ip, 0))
        s.settimeout(timeout_s)
        s.sendto(packet, (server, 53))
        deadline = start + timeout_s
        while True:
            try:
                msg, peer = s.recvfrom(4096)
            except socket.timeout:
                return {"server": server, "name": name, "type": qtype, "timeout": True,
                        "elapsed_ms": round((time.monotonic() - start) * 1000)}
            if peer[0] != server:
                continue  # a stray datagram is not the answer
            try:
                res = parse_response(msg, txid)
            except ValueError:
                if time.monotonic() >= deadline:
                    raise
                continue
            return {"server": server, "name": name, "type": qtype, "timeout": False,
                    "elapsed_ms": round((time.monotonic() - start) * 1000), **res}
