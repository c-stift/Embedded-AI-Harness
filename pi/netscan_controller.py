"""
Netscan Controller — TCP connect check of one host on the bench AP network
(FR-039).

Verifies a DUT's claim that it exposes no listening service. The target rules
are enforced in `select_target` before any connection is made: in AP mode a
single IPv4 address inside the AP subnet, never the Pi itself; in station mode
(the bench joined a DUT's own AP) only that AP. The caller (the portal, as
composition root) supplies the subnet and the Pi's AP address, so this module
does not depend on the WiFi controller.
"""

import concurrent.futures
import errno
import ipaddress
import logging
import socket
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_IN_FLIGHT = 128       # TCP first pass
UDP_IN_FLIGHT = 16        # UDP first pass: a small DUT drops datagrams it cannot buffer and then sends no ICMP
RETRY_IN_FLIGHT = 4       # re-probes of ports that stayed silent
RETRIES = 2               # extra probes for a silent port before its silence counts
CONNECT_TIMEOUT_S = 1.0
UDP_WAIT_S = 1.0          # wait for ICMP port unreachable after one datagram
OPEN, CLOSED, SILENT = "open", "closed", "silent"
PROTOCOLS = ("tcp", "udp")
DEFAULT_PORTS = "1-65535"
DEFAULT_TIMEOUT_S = 120.0
MIN_TIMEOUT_S = 1.0
MAX_TIMEOUT_S = 600.0

# ---------------------------------------------------------------------------
# Pure core
# ---------------------------------------------------------------------------


def validate_target(host, subnet: str, self_ip: str) -> str:
    """Return the normalised address, or raise ValueError naming the reason."""
    if not isinstance(host, str) or "/" in host:
        raise ValueError("host must be a single IPv4 address")
    try:
        addr = ipaddress.IPv4Address(host.strip())
    except ipaddress.AddressValueError:
        raise ValueError("host must be a single IPv4 address") from None
    net = ipaddress.IPv4Network(subnet, strict=True)
    if addr not in net:
        raise ValueError(f"host {addr} is outside the AP subnet {net}")
    if addr in (net.network_address, net.broadcast_address):
        raise ValueError(f"host {addr} is the network or broadcast address")
    if addr == ipaddress.IPv4Address(self_ip):
        raise ValueError(f"host {addr} is the testbench itself")
    return str(addr)


def validate_sta_target(host, gateway: str, self_ip: str) -> str:
    """Station mode: the bench has joined a device's own AP, so the one host it may scan is that AP (the
    gateway it was given), never itself and nothing else on that network."""
    if not gateway:
        raise ValueError("station mode without a gateway: nothing to scan")
    if not isinstance(host, str) or "/" in host:
        raise ValueError("host must be a single IPv4 address")
    try:
        addr = ipaddress.IPv4Address(host.strip())
    except ipaddress.AddressValueError:
        raise ValueError("host must be a single IPv4 address") from None
    if self_ip and addr == ipaddress.IPv4Address(self_ip):
        raise ValueError(f"host {addr} is the testbench itself")
    if addr != ipaddress.IPv4Address(gateway):
        raise ValueError(f"in station mode only the joined AP {gateway} may be scanned")
    return str(addr)


def select_target(host, sta: dict, ap_subnet: str, ap_ip: str) -> str:
    """AP mode: a device on the bench AP's subnet (validate_target). Station mode: the joined AP."""
    if sta.get("active"):
        return validate_sta_target(host, sta.get("gateway", ""), sta.get("ip", ""))
    return validate_target(host, ap_subnet, ap_ip)


def parse_ports(spec) -> list:
    """Parse "22,80,1000-2000" into a sorted, de-duplicated list of ports."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("ports must be a non-empty string")
    ports = set()
    for item in spec.split(","):
        item = item.strip()
        lo_s, sep, hi_s = item.partition("-")
        if not lo_s.isdigit() or (sep and not hi_s.isdigit()):
            raise ValueError(f"bad port item {item!r}")
        lo = int(lo_s)
        hi = int(hi_s) if sep else lo
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"port item {item!r} is outside 1-65535 or reversed")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


def parse_protocol(value) -> str:
    """"tcp" (default) or "udp"; anything else is refused."""
    if value is None:
        return "tcp"
    if value not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {PROTOCOLS}")
    return value


def clamp_timeout(value) -> float:
    """The total budget in seconds, within MIN_TIMEOUT_S..MAX_TIMEOUT_S."""
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
# Scan
# ---------------------------------------------------------------------------


def _tcp_probe(host: str, port: int) -> str:
    """OPEN on a completed connect, CLOSED on a refusal (RST), SILENT when nothing came back in time."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(CONNECT_TIMEOUT_S)
        rc = s.connect_ex((host, port))
    if rc == 0:
        return OPEN
    # Only a refusal is the port's answer; a timeout or an unreachable host (ARP lost under load) is not.
    return CLOSED if rc == errno.ECONNREFUSED else SILENT


def _udp_probe(host: str, port: int) -> str:
    """One datagram to a connected UDP socket. A closed port answers with ICMP port unreachable, which Linux
    reports as ConnectionRefusedError on the socket (CLOSED); a reply is OPEN; no answer within UDP_WAIT_S is
    SILENT — open or filtered, or the datagram was dropped."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(UDP_WAIT_S)
        s.connect((host, port))
        try:
            s.send(b"\x00")
            s.recv(512)
            return OPEN
        except ConnectionRefusedError:
            return CLOSED
        except socket.timeout:
            return SILENT


def classify(protocol: str, states: list) -> str:
    """Fold the answers one port gave across its probes into the reported verdict.

    An answer outranks silence: one OPEN makes the port open, one CLOSED (RST / ICMP unreachable) makes it
    closed — a dropped probe is silent, never an answer. Only a port silent on every probe stays SILENT,
    which TCP reports as not open and UDP as open (open or filtered: UDP cannot tell them apart)."""
    if OPEN in states:
        return OPEN
    if CLOSED in states:
        return CLOSED
    return OPEN if protocol == "udp" else SILENT


def _pass(probe, host: str, ports: list, limit: int, deadline: float, wait_s: float) -> dict:
    """Probe each port once, at most `limit` at a time, until the budget would be overrun.
    Returns {port: state} for the ports that were probed."""
    states = {}
    pending = iter(ports)
    with concurrent.futures.ThreadPoolExecutor(max_workers=limit) as pool:
        in_flight = {}
        while True:
            while len(in_flight) < limit and time.monotonic() + wait_s <= deadline:
                port = next(pending, None)
                if port is None:
                    break
                in_flight[pool.submit(probe, host, port)] = port
            if not in_flight:
                break
            done, _ = concurrent.futures.wait(
                in_flight, timeout=max(0.0, deadline - time.monotonic()) + wait_s,
                return_when=concurrent.futures.FIRST_COMPLETED)
            if not done:
                break
            for fut in done:
                states[in_flight.pop(fut)] = fut.result()
    return states


def scan(host: str, ports: list, timeout_s: float, protocol: str = "tcp") -> dict:
    """Check `ports` on an already validated `host` within timeout_s (TCP connect or UDP probe).

    A first pass probes every port; every port that stayed silent is probed again, RETRIES times, a few at a
    time. A small DUT flooded with probes drops some of them and answers nothing, so one silent probe is no
    verdict: the retries are what keep a dropped SYN from hiding an open TCP port and a dropped datagram from
    showing a closed UDP port as open."""
    udp = protocol == "udp"
    probe = _udp_probe if udp else _tcp_probe
    wait_s = UDP_WAIT_S if udp else CONNECT_TIMEOUT_S
    start = time.monotonic()
    deadline = start + timeout_s
    seen = {p: [s] for p, s in _pass(probe, host, ports, UDP_IN_FLIGHT if udp else MAX_IN_FLIGHT,
                                       deadline, wait_s).items()}
    retried = 0
    for _ in range(RETRIES):
        silent = [p for p in sorted(seen) if all(s == SILENT for s in seen[p])]
        if not silent:
            break
        again = _pass(probe, host, silent, RETRY_IN_FLIGHT, deadline, wait_s)
        retried += len(again)
        for p, s in again.items():
            seen[p].append(s)
        if len(again) < len(silent):
            break  # budget spent
    verdicts = {p: classify(protocol, s) for p, s in seen.items()}
    open_ports = sorted(p for p, v in verdicts.items() if v == OPEN)
    silent_ports = sorted(p for p, s in seen.items() if all(x == SILENT for x in s))
    complete = len(seen) == len(ports)
    elapsed = round(time.monotonic() - start, 1)
    logger.info("portscan %s %s: %d/%d ports, open=%s, silent=%d, retried=%d, complete=%s",
                protocol, host, len(seen), len(ports), open_ports, len(silent_ports), retried, complete)
    return {"host": host, "protocol": protocol, "open": open_ports, "silent": silent_ports,
            "scanned": len(seen), "retried": retried, "complete": complete, "elapsed_s": elapsed}
