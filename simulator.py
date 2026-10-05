"""
simulator.py - Creates FAKE network traffic for the demo.

We mix normal users with 4 kinds of attackers, so we can show the
NIDPS working without needing a real attack or admin rights.

  Normal users     192.168.1.10 - 192.168.1.14   (web browsing, DNS)
  Port scanner     10.0.0.66                      (tries ports 1..300)
  SYN flooder      172.16.5.99                    (hundreds of SYNs per second)
  Ping flooder     10.0.0.77                      (hundreds of pings per second)
  Blacklisted IP   203.0.113.50                   (known bad IP)
"""

import random

SERVER = "192.168.1.1"   # the machine we are protecting

NORMAL_USERS = [f"192.168.1.{i}" for i in range(10, 15)]
PORT_SCANNER = "10.0.0.66"
SYN_FLOODER = "172.16.5.99"
PING_FLOODER = "10.0.0.77"
BLACKLISTED = "203.0.113.50"


def _packet(t, src, proto, dport=None, flags=None):
    return {
        "time": round(t, 3),
        "src": src,
        "dst": SERVER,
        "proto": proto,
        "dport": dport,
        "flags": flags,
    }


def normal_traffic(duration):
    """Normal users: a few packets per second to web (80/443) and DNS (53)."""
    packets = []
    for user in NORMAL_USERS:
        t = random.uniform(0, 1)
        while t < duration:
            choice = random.random()
            if choice < 0.7:
                packets.append(_packet(t, user, "TCP", random.choice([80, 443]),
                                       random.choice(["S", "A", "PA"])))
            elif choice < 0.9:
                packets.append(_packet(t, user, "UDP", 53))
            else:
                packets.append(_packet(t, user, "ICMP"))
            t += random.uniform(0.2, 0.8)
    return packets


def port_scan(start):
    """Attacker tries ports 1, 2, 3 ... 300 one after another to find open ones."""
    return [_packet(start + port * 0.025, PORT_SCANNER, "TCP", port, "S")
            for port in range(1, 301)]


def syn_flood(start):
    """Attacker sends 3000 SYN packets in ~3 seconds to fill up the server."""
    return [_packet(start + i * 0.001, SYN_FLOODER, "TCP", 80, "S")
            for i in range(3000)]


def ping_flood(start):
    """Attacker sends 1500 pings in ~3 seconds."""
    return [_packet(start + i * 0.002, PING_FLOODER, "ICMP")
            for i in range(1500)]


def blacklisted_visit(start):
    """A known-bad IP tries to connect to the web server a few times."""
    return [_packet(start + i * 0.5, BLACKLISTED, "TCP", 443, "S")
            for i in range(20)]


def generate_traffic(duration=30, attacks=None, seed=42):
    """
    Build the full list of packets, sorted by time.
    `attacks` = which attacks to include (default: all four).
    """
    random.seed(seed)
    if attacks is None:
        attacks = ["Port Scan", "SYN Flood", "Ping Flood", "Blacklisted IP"]

    packets = normal_traffic(duration)
    if "Port Scan" in attacks:
        packets += port_scan(start=5)
    if "SYN Flood" in attacks:
        packets += syn_flood(start=12)
    if "Ping Flood" in attacks:
        packets += ping_flood(start=18)
    if "Blacklisted IP" in attacks:
        packets += blacklisted_visit(start=22)

    packets.sort(key=lambda p: p["time"])
    return packets
