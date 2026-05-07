import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import sniff, IP, TCP, UDP

# Page Config
st.set_page_config(page_title="Data Science Network Analyzer", layout="wide")
st.title("📡 Real-Time Network Packet Analyzer")

# Initialize session state to store our data
if 'df_data' not in st.session_state:
    st.session_state.df_data = pd.DataFrame(columns=['Source', 'Destination', 'Protocol', 'Length'])

# --- Sidebar ---
st.sidebar.header("Capture Settings")
num_packets = st.sidebar.slider("Packets to capture", 10, 200, 50)

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
    sniff(prn=packet_callback, count=num_packets)
    return pd.DataFrame(packets_captured)

# --- UI Buttons ---
# --- UI Buttons ---
if st.sidebar.button("🚀 Start Live Sniffing"):
    with st.spinner("Sniffing network traffic..."):
        try:
            # Try to capture live traffic (Works on your laptop)
            new_data = capture_logic()
            st.session_state.df_data = pd.concat([st.session_state.df_data, new_data], ignore_index=True)
            st.success(f"Successfully captured {len(new_data)} packets!")
            
        except Exception as e:
            # FALLBACK: If live sniffing fails (Works on Streamlit Cloud)
            st.sidebar.warning("⚠️ Live Sniffing restricted in Cloud.")
            
            try:
                # Load your uploaded CSV file instead
                new_data = pd.read_csv("network_traffic.csv")
                st.session_state.df_data = new_data
                st.info("Showing data from 'network_traffic.csv' instead.")
            except FileNotFoundError:
                st.sidebar.error("CSV file not found on GitHub!")

# --- Dashboard Layout ---
df = st.session_state.df_data

if not df.empty:
    # 1. Metrics
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Packets", len(df))
    m2.metric("Avg Packet Size", f"{round(df['Length'].mean(), 1)} B")
    m3.metric("Most Active IP", df['Source'].mode()[0])

    # 2. Charts
    # 2. Charts Section
    c1, c2 = st.columns(2)
    with c1:
        st.write("### Protocol Distribution")
        fig1, ax1 = plt.subplots()
        df['Protocol'].value_counts().plot(kind='pie', autopct='%1.1f%%', ax=ax1, colors=['#3498db', '#2ecc71', '#e74c3c'])
        st.pyplot(fig1)
    
    with c2:
        st.write("### Packet Size Analysis")
        fig2, ax2 = plt.subplots()
        sns.histplot(df['Length'], kde=True, ax=ax2, color='purple')
        st.pyplot(fig2)

    # 3. New Row for Top IPs (Full Width)
    st.write("### Top 5 Source IP Addresses (Traffic Volume)")
    fig3, ax3 = plt.subplots(figsize=(10, 3)) # Slightly wider/shorter for better fit
    top_ips = df['Source'].value_counts().head(5)
    sns.barplot(x=top_ips.values, y=top_ips.index, ax=ax3, palette="magma")
    plt.xlabel("Number of Packets")
    st.pyplot(fig3)

    # 3. Data Table
    st.write("### Captured Traffic Logs")
    st.dataframe(df.tail(20), use_container_width=True)
else:
    st.info("The dashboard is empty. Use the sidebar to start capturing live data.")
