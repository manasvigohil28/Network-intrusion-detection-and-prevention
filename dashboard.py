"""
dashboard.py - Web dashboard for the NIDPS (built with Streamlit).

Run it with:
    streamlit run dashboard.py

Use the sidebar to switch between IDS mode (detect only) and IPS mode
(detect + block), choose which attacks to simulate, and change thresholds.
"""

import altair as alt
import pandas as pd
import streamlit as st

import config
from detector import Detector
from main import process_packets
from prevention import Firewall
from simulator import generate_traffic

ALLOWED_COLOR = "#2a78d6"   # blue
DROPPED_COLOR = "#eb6834"   # orange

st.set_page_config(page_title="NIDPS Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Intrusion Detection & Prevention System")
st.caption("Simulated network traffic is checked against 4 rules. Attackers are detected and (in IPS mode) blocked.")

# ---------------- Sidebar: settings ----------------
st.sidebar.header("Settings")
prevention = st.sidebar.toggle("Prevention ON (IPS mode)", value=True,
                               help="ON = detect and block attackers. OFF = only detect (IDS mode).")
attacks = st.sidebar.multiselect(
    "Attacks to simulate",
    ["Port Scan", "SYN Flood", "Ping Flood", "Blacklisted IP"],
    default=["Port Scan", "SYN Flood", "Ping Flood", "Blacklisted IP"],
)
st.sidebar.subheader("Detection thresholds")
port_limit = st.sidebar.slider(f"Port scan: max different ports in {config.PORT_SCAN_WINDOW}s",
                               1, 300, config.PORT_SCAN_THRESHOLD)
syn_limit = st.sidebar.slider("SYN flood: max SYN packets per second", 5, 1500, config.SYN_FLOOD_THRESHOLD)
icmp_limit = st.sidebar.slider("Ping flood: max pings per second", 5, 1000, config.ICMP_FLOOD_THRESHOLD)
st.sidebar.subheader("Blacklist")
st.sidebar.code("\n".join(sorted(config.BLACKLIST)))

# ---------------- Run the NIDPS ----------------
packets = generate_traffic(attacks=attacks)
detector = Detector(port_limit, syn_limit, icmp_limit)
firewall = Firewall(use_windows_firewall=False)
results, alerts = process_packets(packets, detector, firewall, prevention)

df = pd.DataFrame(results)
# The packet that triggers an alert is also stopped when prevention is on
df["outcome"] = "Allowed"
if prevention:
    df.loc[df["status"].isin(["DROPPED", "ALERT"]), "outcome"] = "Dropped"

# ---------------- Headline numbers ----------------
st.subheader("IPS mode: detect + block" if prevention else "IDS mode: detect only (nothing is blocked)")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Packets analysed", f"{len(df):,}")
c2.metric("Allowed", f"{(df['outcome'] == 'Allowed').sum():,}")
c3.metric("Dropped", f"{(df['outcome'] == 'Dropped').sum():,}")
c4.metric("Alerts raised", len(alerts))
c5.metric("Blocked IPs", len(firewall.blocked))

# ---------------- Alerts & blocked IPs ----------------
left, right = st.columns([3, 2])
with left:
    st.markdown("#### 🚨 Alerts")
    if alerts:
        alerts_df = pd.DataFrame(alerts).rename(columns={
            "time": "Time (s)", "src": "Attacker IP", "attack": "Attack", "details": "Why"})
        alerts_df["Action"] = "Blocked" if prevention else "Alert only"
        st.dataframe(alerts_df, hide_index=True)
    else:
        st.success("No attacks detected.")
with right:
    st.markdown("#### 🚫 Blocked IPs")
    if firewall.blocked:
        st.dataframe(pd.DataFrame(firewall.blocked.items(), columns=["IP address", "Reason"]),
                     hide_index=True)
    elif prevention:
        st.info("No IPs blocked.")
    else:
        st.warning("Prevention is OFF, so attackers are not blocked.")

# ---------------- Charts ----------------
st.markdown("#### Traffic per second")
st.caption("When prevention is ON, attack traffic is dropped right after it is detected.")
colors = alt.Scale(domain=["Allowed", "Dropped"], range=[ALLOWED_COLOR, DROPPED_COLOR])
packets_axis = alt.Scale(zero=True)

df["second"] = df["time"].astype(int)
per_second = df.groupby(["second", "outcome"]).size().reset_index(name="packets")
st.altair_chart(
    alt.Chart(per_second).mark_bar().encode(
        x=alt.X("second:O", title="Time (seconds)"),
        y=alt.Y("packets:Q", title="Packets", stack=True, scale=packets_axis),
        color=alt.Color("outcome:N", scale=colors, title=None, legend=alt.Legend(orient="bottom")),
        tooltip=[alt.Tooltip("second:O", title="Second"), alt.Tooltip("outcome:N", title="Outcome"),
                 alt.Tooltip("packets:Q", title="Packets")],
    ).properties(height=320),
)

st.markdown("#### Packets per source IP (top 10)")
per_ip = df.groupby(["src", "outcome"]).size().reset_index(name="packets")
top_ips = per_ip.groupby("src")["packets"].sum().nlargest(10).index.tolist()
st.altair_chart(
    alt.Chart(per_ip[per_ip["src"].isin(top_ips)]).mark_bar().encode(
        y=alt.Y("src:N", title="Source IP", sort=top_ips, axis=alt.Axis(labelOverlap=False)),
        x=alt.X("packets:Q", title="Packets", stack=True, scale=packets_axis),
        color=alt.Color("outcome:N", scale=colors, title=None, legend=alt.Legend(orient="bottom")),
        tooltip=[alt.Tooltip("src:N", title="Source IP"), alt.Tooltip("outcome:N", title="Outcome"),
                 alt.Tooltip("packets:Q", title="Packets")],
    ).properties(height=320),
)

# ---------------- Raw packets ----------------
with st.expander("See individual packets"):
    show = st.multiselect("Show outcome", ["Allowed", "Dropped"], default=["Dropped"])
    view = df[df["outcome"].isin(show)][["time", "src", "dst", "proto", "dport", "flags", "outcome"]]
    st.dataframe(view.head(500), hide_index=True)
    st.caption(f"Showing first {min(len(view), 500)} of {len(view):,} packets.")
