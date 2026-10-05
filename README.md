# Network Intrusion Detection & Prevention System (NIDPS)

A simple Python project that **watches network traffic**, **detects attacks** using rules,
and **blocks the attacker's IP address**. It includes a **Streamlit web dashboard**.

---

## 1. The basic idea

| Term | Meaning | In this project |
|------|---------|-----------------|
| **IDS** (Intrusion Detection System) | Watches traffic and **raises an alert** when it sees an attack. It does not stop it. | `detector.py` |
| **IPS** (Intrusion Prevention System) | Detects the attack **and blocks it** automatically. | `prevention.py` |
| **NIDPS** | Both together. | `main.py` + `dashboard.py` |

Think of it like a building: an **IDS is a CCTV camera** (it sees the thief and rings the alarm),
and an **IPS is a security guard** (it sees the thief and locks the door).

---

## 2. Attacks we detect

| Attack | What the attacker does | Our rule |
|--------|------------------------|----------|
| **Port scan** | Knocks on many ports (22, 23, 80, …) to find which services are open. Usually the first step of a hack. | One IP touches **more than 15 different ports in 5 seconds** |
| **SYN flood** (DoS) | Sends thousands of "I want to connect" (TCP SYN) packets but never finishes the connection. The server runs out of memory waiting. | One IP sends **more than 50 SYN packets in 1 second** |
| **Ping flood** (DoS) | Sends so many ping (ICMP) packets that the network or server gets overloaded. | One IP sends **more than 30 pings in 1 second** |
| **Blacklisted IP** | A connection from an IP already known to be malicious. | Source IP is in the **blacklist** |

All numbers can be changed in `config.py` or with the sliders on the dashboard.

> This is called **signature/rule-based detection**: we know what an attack looks like
> and check every packet against those rules.

---

## 3. How it works (flow)

```
   Packet arrives
        │
        ▼
 Is sender already blocked? ──Yes──► DROP packet  (prevention)
        │ No
        ▼
 Check the 4 detection rules  (detector.py)
        │
   ┌────┴─────┐
 Attack?     No attack
   │            │
   ▼            ▼
 ALERT +      ALLOW packet
 write log
 + BLOCK IP  (prevention.py)
```

**Sliding time window:** for each IP, we keep only the packets from the last few seconds.
If the count inside that window goes above the limit, it's an attack. Normal users send
only a few packets per second, so they never reach the limit.

---

## 4. Files

| File | What it does |
|------|--------------|
| `config.py` | All settings: thresholds, blacklist, IPS on/off |
| `simulator.py` | Creates fake traffic: 5 normal users + 4 attackers |
| `detector.py` | The 4 detection rules (the **IDS**) |
| `prevention.py` | Keeps the list of blocked IPs (the **IPS**). Can also add rules to the Windows Firewall. |
| `main.py` | Runs everything in the terminal and writes `alerts.log` |
| `dashboard.py` | Streamlit web dashboard |

### Simulated traffic

| Who | IP | Behaviour |
|-----|----|-----------|
| Normal users | 192.168.1.10 – 192.168.1.14 | Web browsing (ports 80/443) and DNS, a few packets per second |
| Port scanner | 10.0.0.66 | Tries ports 1 to 300 |
| SYN flooder | 172.16.5.99 | 3000 SYN packets in 3 seconds |
| Ping flooder | 10.0.0.77 | 1500 pings in 3 seconds |
| Blacklisted IP | 203.0.113.50 | Tries to connect to the web server |
| Protected server | 192.168.1.1 | The machine we are defending |

---

## 5. How to run

**Install (one time):**
```bash
pip install -r requirements.txt
```

**Dashboard (main demo):**
```bash
streamlit run dashboard.py
```
It opens in the browser at http://localhost:8501.

**Terminal version:**
```bash
python main.py
```
```bash
python main.py --ids-only
```

**Live mode (optional):** sniffs real network traffic. It needs [Npcap](https://npcap.com)
installed and a terminal opened **as Administrator**.
```bash
python main.py --live
```

### Demo tips
1. Open the dashboard with **Prevention ON**. Show the 4 alerts, the 4 blocked IPs, and
   the orange "Dropped" bars in the traffic chart.
2. Switch **Prevention OFF** (IDS mode). Alerts still appear, but nothing is blocked and
   all the attack traffic is allowed through. This shows the **difference between IDS and IPS**.
3. Untick some attacks in the sidebar, or move a threshold slider very high, and the
   attack is no longer detected. This shows how thresholds affect detection.

---

## 6. Limitations and future work
- Rule-based detection only catches **known** attack patterns. New (zero-day) attacks
  need **anomaly detection** or **machine learning**.
- Thresholds that are too low cause **false positives** (normal users blocked).
  Thresholds that are too high cause **false negatives** (attacks missed).
- Attackers can **spoof** (fake) their IP, so blocking by IP is not always enough.
- Future work: an ML model trained on a dataset such as NSL-KDD or CICIDS2017, email/SMS
  alerts, and automatic unblocking after a timeout.

---

## 7. Viva questions (quick answers)

1. **What is an IDS?** A system that monitors network traffic and raises alerts on suspicious activity.
2. **What is an IPS?** An IDS that can also automatically block or drop the malicious traffic.
3. **IDS vs IPS?** An IDS is passive (it only alerts). An IPS is active (it alerts and blocks).
4. **Types of IDS?** NIDS (network-based, watches the network) and HIDS (host-based, watches one computer). Ours is a NIDS.
5. **Detection methods?** Signature/rule-based (known patterns, which is what we use) and anomaly-based (learns what's normal and flags anything unusual).
6. **What is a port scan?** Checking many ports on a target to find open services. Tools like **Nmap** do this.
7. **What is a SYN flood?** A DoS attack that abuses the TCP 3-way handshake (SYN → SYN-ACK → ACK). The attacker sends SYNs but never the final ACK, so the server keeps half-open connections until it runs out of resources.
8. **What is a ping flood?** A DoS attack that overloads the target with ICMP echo (ping) requests.
9. **What is DoS / DDoS?** Denial of Service makes a service unavailable. DDoS is the same attack from many machines at once.
10. **What is a false positive?** Normal traffic wrongly flagged as an attack. A **false negative** is a real attack that was missed.
11. **What is a sliding window?** We only count packets from the last N seconds, so old packets don't affect the decision.
12. **How do you block an IP?** We add it to a block list and drop its packets. On Windows it can also run `netsh advfirewall firewall add rule … action=block`.
13. **Which libraries did you use?** Python, **Scapy** (packet capture), **Streamlit** (dashboard), **pandas** (tables and charts).
14. **Real-world tools?** **Snort**, **Suricata** and **Zeek** are popular open-source IDS/IPS.
15. **Why simulated traffic?** It's safe, legal, and gives the same result every time. Real attacks should only be tested on networks you own or have permission to test.
