import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import sniff, IP, TCP, UDP
import time

# 1. PAGE CONFIG & MODERN THEME
st.set_page_config(page_title="Pro Network Analyzer", layout="wide", page_icon="🛡️")

# Custom CSS for a "Dark Mode" Innovative look
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stMetric {
        background-color: #1f2937;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #3b82f6;
    }
    div.stButton > button:first-child {
        background-color: #3b82f6;
        color: white;
        width: 100%;
        border-radius: 5px;
        height: 3em;
        font-weight: bold;
    }
    .status-box {
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- App Title Section ---
st.title("🛡️ CyberPulse: Real-Time Packet Engine")
st.markdown("---")

# Initialize session state
if 'df_data' not in st.session_state:
    st.session_state.df_data = pd.DataFrame(columns=['Source', 'Destination', 'Protocol', 'Length'])

# --- Sidebar (Settings) ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    st.header("Control Center")
    num_packets = st.slider("Target Packets", 10, 500, 50)
    
    st.markdown("### Actions")
    start_btn = st.button("🚀 INITIATE SCAN")
    clear_btn = st.button("🗑️ PURGE LOGS")

# --- Sniffer Logic ---
def capture_logic():
    packets_captured = []
    def packet_callback(packet):
        if packet.haslayer(IP):
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
            packets_captured.append({
                "Source": packet[IP].src,
                "Destination": packet[IP].dst,
                "Protocol": proto,
                "Length": len(packet)
            })
    sniff(prn=packet_callback, count=num_packets, timeout=15)
    return pd.DataFrame(packets_captured)

# --- Button Handling ---
if start_btn:
    progress_bar = st.progress(0)
    for i in range(100):
        time.sleep(0.01)
        progress_bar.progress(i + 1)
    
    new_data = capture_logic()
    st.session_state.df_data = pd.concat([st.session_state.df_data, new_data], ignore_index=True)
    st.toast("Scan Complete!", icon='✅')

if clear_btn:
    st.session_state.df_data = pd.DataFrame(columns=['Source', 'Destination', 'Protocol', 'Length'])
    st.rerun()

# --- Dashboard Layout ---
df = st.session_state.df_data

if not df.empty:
    # Row 1: Metrics (Cards)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        st.metric("Avg Size", f"{int(df['Length'].mean())} B")
    with col3:
        st.metric("TCP Count", len(df[df['Protocol']=='TCP']))
    with col4:
        st.metric("UDP Count", len(df[df['Protocol']=='UDP']))

    st.markdown("### 📊 Network Insights")
    
    # Row 2: Charts
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Traffic Composition**")
        fig1, ax1 = plt.subplots(facecolor='#0e1117')
        df['Protocol'].value_counts().plot(kind='pie', autopct='%1.1f%%', ax=ax1, 
                                        colors=['#3b82f6', '#10b981', '#ef4444'], textprops={'color':"w"})
        st.pyplot(fig1)
    
    with c2:
        st.markdown("**Bandwidth Distribution**")
        fig2, ax2 = plt.subplots(facecolor='#0e1117')
        sns.histplot(df['Length'], kde=True, ax=ax2, color='#3b82f6')
        ax2.tick_params(colors='white')
        ax2.xaxis.label.set_color('white')
        ax2.yaxis.label.set_color('white')
        st.pyplot(fig2)

    # Row 3: Interactive Table
    st.markdown("### 📜 Real-Time Logs")
    st.dataframe(df.tail(50), use_container_width=True)

else:
    st.info("System Standby. Please initiate a scan from the Control Center to view telemetry.")
