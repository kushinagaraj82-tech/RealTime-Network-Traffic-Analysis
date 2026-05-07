import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import sniff, IP, TCP, UDP

# 1. Page Configuration
st.set_page_config(page_title="Network Traffic Analyzer", layout="wide", page_icon="📡")

# --- Sidebar ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3067/3067451.png", width=100)
    st.title("Control Panel")
    st.markdown("---")
    
    st.header("Capture Settings")
    num_packets = st.slider("Packets to capture", 10, 500, 50)
    
    st.markdown("### Execution")
    start_btn = st.button("🚀 Start Live Sniffing")
    clear_btn = st.button("🗑️ Clear Data")

# --- Always Visible Title ---
st.title("📡 Real-Time Network Packet Analyzer")

# Initialize session state to store our data
if 'df_data' not in st.session_state:
    st.session_state.df_data = pd.DataFrame(columns=['Source', 'Destination', 'Protocol', 'Length'])

# --- The Sniffer Logic ---
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

    # Start sniffing
    sniff(prn=packet_callback, count=num_packets, timeout=20)
    return pd.DataFrame(packets_captured)

# --- UI Buttons Logic ---
if start_btn:
    with st.spinner("Sniffing network traffic... Please browse a website now!"):
        new_data = capture_logic()
        if not new_data.empty:
            st.session_state.df_data = pd.concat([st.session_state.df_data, new_data], ignore_index=True)
            # Re-added the green success message here
            st.success(f"Capture Successful! Added {len(new_data)} packets to the analyzer.")
        else:
            st.error("No packets captured. Check your Admin permissions/Npcap.")

if clear_btn:
    st.session_state.df_data = pd.DataFrame(columns=['Source', 'Destination', 'Protocol', 'Length'])
    st.rerun()

# --- Dashboard Layout ---
df = st.session_state.df_data

if not df.empty:
    # 1. Metrics
    st.markdown("### 📈 Real-Time Metrics")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Packets", len(df))
    m2.metric("Avg Packet Size", f"{round(df['Length'].mean(), 1)} B")
    m3.metric("TCP Packets", len(df[df['Protocol'] == "TCP"]))
    m4.metric("Most Active IP", df['Source'].mode()[0])

    # 2. Charts Section
    c1, c2 = st.columns(2)
    with c1:
        st.write("### Protocol Distribution")
        fig1, ax1 = plt.subplots()
        df['Protocol'].value_counts().plot(kind='pie', autopct='%1.1f%%', ax=ax1, colors=['#3498db', '#2ecc71', '#e74c3c'])
        plt.ylabel("") 
        st.pyplot(fig1)
    
    with c2:
        st.write("### Packet Size Analysis")
        fig2, ax2 = plt.subplots()
        sns.histplot(df['Length'], kde=True, ax=ax2, color='purple')
        plt.xlabel("Size (Bytes)")
        st.pyplot(fig2)

    # 3. Top IPs
    st.write("### Top 5 Source IP Addresses (Traffic Volume)")
    fig3, ax3 = plt.subplots(figsize=(10, 3)) 
    top_ips = df['Source'].value_counts().head(5)
    sns.barplot(x=top_ips.values, y=top_ips.index, ax=ax3, palette="magma")
    plt.xlabel("Number of Packets")
    st.pyplot(fig3)

    # 4. Data Table
    st.write("### Captured Traffic Logs (Latest 20)")
    st.dataframe(df.tail(20), use_container_width=True)

else:
    # This only shows when no data has been captured yet
    st.info("Status: System Ready. Awaiting live packet ingestion.")
    st.write("Use the sidebar control panel to start a scan. Captured telemetry will appear here.")
