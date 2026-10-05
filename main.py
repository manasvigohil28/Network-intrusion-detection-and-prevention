"""
main.py - Runs the Network Intrusion Detection & Prevention System.

How every packet is handled:
    1. Is the sender already blocked?  -> DROP the packet (prevention)
    2. Otherwise check it with the detector rules
    3. Attack found?  -> raise ALERT, write to log, BLOCK the sender
    4. No attack      -> ALLOW the packet

Run in the terminal:
    python main.py            (simulated traffic - works everywhere)
    python main.py --live     (real traffic - needs Scapy + Npcap + Administrator)
"""

import argparse
import os
from datetime import datetime

import config
from detector import Detector
from prevention import Firewall

# Colours for the terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def write_log(alert, action):
    line = (f"{datetime.now():%Y-%m-%d %H:%M:%S} | {alert['attack']:<15} | "
            f"src={alert['src']:<15} | {alert['details']} | action={action}\n")
    with open(config.LOG_FILE, "a") as f:
        f.write(line)


def handle_packet(packet, detector, firewall, prevention=True):
    """
    Process one packet. Returns (status, alerts)
    status is "DROPPED", "ALERT" or "ALLOWED".
    """
    if prevention and firewall.is_blocked(packet["src"]):
        return "DROPPED", []

    alerts = detector.inspect(packet)
    for alert in alerts:
        action = "BLOCKED" if prevention else "ALERT ONLY"
        if prevention:
            firewall.block(alert["src"], alert["attack"])
        write_log(alert, action)
    return ("ALERT" if alerts else "ALLOWED"), alerts


def process_packets(packets, detector, firewall, prevention=True):
    """Run a whole list of packets through the NIDPS. Used by the dashboard too."""
    results, all_alerts = [], []
    for packet in packets:
        status, alerts = handle_packet(packet, detector, firewall, prevention)
        results.append({**packet, "status": status})
        all_alerts.extend(alerts)
    return results, all_alerts


def print_alert(alert, prevention):
    action = f"{RED}-> IP BLOCKED{RESET}" if prevention else f"{YELLOW}-> alert only{RESET}"
    print(f"{RED}[ALERT]{RESET} t={alert['time']:>6}s  {alert['attack']:<15} "
          f"from {alert['src']:<15} ({alert['details']}) {action}")


def run_simulation(prevention):
    from simulator import generate_traffic

    packets = generate_traffic()
    print(f"Generated {len(packets)} simulated packets. Analysing...\n")

    detector, firewall = Detector(), Firewall()
    results, alerts = process_packets(packets, detector, firewall, prevention)
    for alert in alerts:
        print_alert(alert, prevention)

    allowed = sum(r["status"] == "ALLOWED" for r in results)
    dropped = sum(r["status"] == "DROPPED" for r in results)
    print(f"\n{GREEN}===== Summary ====={RESET}")
    print(f"Packets analysed : {len(results)}")
    print(f"Packets allowed  : {allowed}")
    print(f"Packets dropped  : {dropped}")
    print(f"Alerts raised    : {len(alerts)}")
    print(f"Blocked IPs      : {', '.join(firewall.blocked) or 'none'}")
    print(f"Alerts saved to  : {config.LOG_FILE}")


def run_live(prevention):
    """Sniff real packets from the network card (optional bonus mode)."""
    import time
    from scapy.all import ICMP, IP, TCP, UDP, sniff

    detector, firewall = Detector(), Firewall()

    def on_packet(pkt):
        if IP not in pkt:
            return
        packet = {"time": time.time(), "src": pkt[IP].src, "dst": pkt[IP].dst,
                  "proto": "OTHER", "dport": None, "flags": None}
        if TCP in pkt:
            packet.update(proto="TCP", dport=pkt[TCP].dport, flags=str(pkt[TCP].flags))
        elif UDP in pkt:
            packet.update(proto="UDP", dport=pkt[UDP].dport)
        elif ICMP in pkt:
            packet["proto"] = "ICMP"

        _, alerts = handle_packet(packet, detector, firewall, prevention)
        for alert in alerts:
            alert["time"] = datetime.now().strftime("%H:%M:%S")
            print_alert(alert, prevention)

    print("Live mode: sniffing packets... press Ctrl+C to stop.")
    sniff(prn=on_packet, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Network Intrusion Detection & Prevention System")
    parser.add_argument("--live", action="store_true", help="sniff real network traffic (needs admin + Npcap)")
    parser.add_argument("--ids-only", action="store_true", help="only detect, do not block (IDS mode)")
    args = parser.parse_args()
    os.system("")   # turns on terminal colours in older Windows consoles

    prevention = config.PREVENTION_ENABLED and not args.ids_only
    print(f"Mode: {'IPS (detect + block)' if prevention else 'IDS (detect only)'}")

    if args.live:
        run_live(prevention)
    else:
        run_simulation(prevention)
