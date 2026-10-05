"""
detector.py - The INTRUSION DETECTION part (IDS).

It looks at packets one by one and checks them against 4 simple rules:
    1. Blacklisted IP
    2. Port scan
    3. SYN flood
    4. Ping (ICMP) flood

Every packet is a small dictionary, for example:
    {"time": 3.2, "src": "10.0.0.66", "dst": "192.168.1.1",
     "proto": "TCP", "dport": 22, "flags": "S"}
"""

from collections import defaultdict, deque

import config


class Detector:
    def __init__(self, port_scan_threshold=None, syn_threshold=None, icmp_threshold=None):
        # Use values from config.py unless the dashboard gives new ones.
        self.port_scan_threshold = port_scan_threshold or config.PORT_SCAN_THRESHOLD
        self.syn_threshold = syn_threshold or config.SYN_FLOOD_THRESHOLD
        self.icmp_threshold = icmp_threshold or config.ICMP_FLOOD_THRESHOLD

        # Memory of recent packets for each source IP.
        # deque = a list where we can cheaply remove old items from the front.
        self.ports_seen = defaultdict(deque)   # ip -> [(time, port), ...]
        self.syn_times = defaultdict(deque)    # ip -> [time, ...]
        self.icmp_times = defaultdict(deque)   # ip -> [time, ...]

        # Remember which (ip, attack) we already reported, so we alert only once.
        self.already_alerted = set()

    @staticmethod
    def _drop_old(items, now, window, get_time=lambda x: x):
        """Remove entries older than `window` seconds (sliding time window)."""
        while items and now - get_time(items[0]) > window:
            items.popleft()

    def _make_alert(self, packet, attack, details):
        key = (packet["src"], attack)
        if key in self.already_alerted:
            return None
        self.already_alerted.add(key)
        return {
            "time": packet["time"],
            "src": packet["src"],
            "attack": attack,
            "details": details,
        }

    def inspect(self, packet):
        """Check one packet. Returns a list of alerts (empty list = packet looks fine)."""
        alerts = []
        src = packet["src"]
        now = packet["time"]

        # Rule 1: Blacklisted IP
        if src in config.BLACKLIST:
            alerts.append(self._make_alert(packet, "Blacklisted IP", "Source IP is on the blacklist"))

        if packet["proto"] == "TCP":
            # Rule 2: Port scan -> many DIFFERENT ports in a short time
            ports = self.ports_seen[src]
            ports.append((now, packet["dport"]))
            self._drop_old(ports, now, config.PORT_SCAN_WINDOW, get_time=lambda x: x[0])
            unique_ports = {port for _, port in ports}
            if len(unique_ports) > self.port_scan_threshold:
                alerts.append(self._make_alert(
                    packet, "Port Scan",
                    f"{len(unique_ports)} different ports in {config.PORT_SCAN_WINDOW}s"))

            # Rule 3: SYN flood -> too many connection requests (SYN) per second
            if packet.get("flags") == "S":
                syns = self.syn_times[src]
                syns.append(now)
                self._drop_old(syns, now, config.FLOOD_WINDOW)
                if len(syns) > self.syn_threshold:
                    alerts.append(self._make_alert(
                        packet, "SYN Flood",
                        f"{len(syns)} SYN packets in {config.FLOOD_WINDOW}s"))

        elif packet["proto"] == "ICMP":
            # Rule 4: Ping flood -> too many ping packets per second
            pings = self.icmp_times[src]
            pings.append(now)
            self._drop_old(pings, now, config.FLOOD_WINDOW)
            if len(pings) > self.icmp_threshold:
                alerts.append(self._make_alert(
                    packet, "Ping Flood",
                    f"{len(pings)} ICMP packets in {config.FLOOD_WINDOW}s"))

        # Remove the None values (attacks that were already reported before)
        return [a for a in alerts if a is not None]
