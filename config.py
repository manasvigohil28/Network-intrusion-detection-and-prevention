"""
config.py - All the settings for the NIDPS in one place.

Change the numbers here to make detection more or less strict.
"""

# ---------------- Detection thresholds ----------------

# PORT SCAN: if one IP touches more than this many DIFFERENT ports
# within PORT_SCAN_WINDOW seconds, it is a port scan.
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 5          # seconds

# SYN FLOOD: if one IP sends more than this many TCP SYN packets
# within FLOOD_WINDOW seconds, it is a SYN flood (DoS attack).
SYN_FLOOD_THRESHOLD = 50

# PING (ICMP) FLOOD: if one IP sends more than this many ping packets
# within FLOOD_WINDOW seconds, it is a ping flood.
ICMP_FLOOD_THRESHOLD = 30

FLOOD_WINDOW = 1              # seconds

# BLACKLIST: IPs that are already known to be malicious.
# Any packet from these IPs is an attack straight away.
BLACKLIST = {
    "203.0.113.50",
    "198.51.100.23",
}

# ---------------- Prevention settings ----------------

# True  = IPS mode: attackers are blocked automatically.
# False = IDS mode: we only raise alerts, nothing is blocked.
PREVENTION_ENABLED = True

# If True, blocked IPs are ALSO added to the real Windows Firewall
# (needs Administrator rights). Keep False for the demo.
USE_WINDOWS_FIREWALL = False

# ---------------- Output ----------------

LOG_FILE = "alerts.log"
