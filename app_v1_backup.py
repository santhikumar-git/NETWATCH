import streamlit as st
import socket
from datetime import datetime

st.set_page_config(
    page_title="NETWATCH",
    page_icon="🌐",
    layout="wide"
)

st.title("🌐 NETWATCH")
st.subheader("Network Health Monitoring Dashboard")

st.info(
    "Educational project. Checks DNS resolution "
    "for a hostname you are authorised to test."
)

hostname = st.text_input(
    "Enter a hostname",
    value="example.com"
)

if st.button("Check Network", type="primary"):
    if not hostname.strip():
        st.warning("Please enter a hostname.")
    else:
        try:
            addresses = socket.getaddrinfo(
                hostname.strip(),
                None
            )

            ips = sorted(set(
                item[4][0] for item in addresses
            ))

            st.success("DNS resolution successful!")

            st.metric("IP addresses found", len(ips))

            st.write("### Resolved addresses")
            for ip in ips:
                st.write(f"- {ip}")

        except socket.gaierror:
            st.error("DNS resolution failed.")

        st.caption(
            "Checked at: " +
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

st.divider()
st.caption("NETWATCH | Version 1.0")

