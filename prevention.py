"""
prevention.py - The INTRUSION PREVENTION part (IPS).

When the detector finds an attack, we BLOCK the attacker's IP.
After that, every packet from that IP is DROPPED (not allowed in).

Optionally, the IP can also be blocked in the real Windows Firewall
(set USE_WINDOWS_FIREWALL = True in config.py and run as Administrator).
"""

import subprocess

import config


class Firewall:
    def __init__(self, use_windows_firewall=None):
        self.blocked = {}   # ip -> reason it was blocked
        if use_windows_firewall is None:
            use_windows_firewall = config.USE_WINDOWS_FIREWALL
        self.use_windows_firewall = use_windows_firewall

    def is_blocked(self, ip):
        return ip in self.blocked

    def block(self, ip, reason):
        if ip in self.blocked:
            return
        self.blocked[ip] = reason
        if self.use_windows_firewall:
            self._windows_block(ip)

    def unblock(self, ip):
        self.blocked.pop(ip, None)
        if self.use_windows_firewall:
            self._windows_unblock(ip)

    # ---------- Real Windows Firewall (optional) ----------

    @staticmethod
    def _windows_block(ip):
        # Adds an inbound rule: block all traffic from this IP
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=NIDPS Block {ip}", "dir=in", "action=block", f"remoteip={ip}"],
            capture_output=True,
        )

    @staticmethod
    def _windows_unblock(ip):
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=NIDPS Block {ip}"],
            capture_output=True,
        )
