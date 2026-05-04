import streamlit as st
import json, os, glob, requests, time
import pandas as pd
from datetime import datetime

from iot_device import IoTDevice
from decision_engine import decide_execution
from pqc_module import kyber_keygen, kyber_encrypt, kyber_decrypt

EDGE_SERVER_URL = "http://127.0.0.1:8000/offload"
RESULTS_FOLDER = "results"
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# -----------------------------------
# Save Result
# -----------------------------------
def save_result(data):
    filename = datetime.now().strftime("%Y%m%d_%H%M%S.json")
    filepath = os.path.join(RESULTS_FOLDER, filename)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

# -----------------------------------
# Premium UI
# -----------------------------------
st.set_page_config(page_title="Adaptive PQC Dashboard", layout="wide")

st.markdown("""
<style>
.main-title{
font-size:40px;
font-weight:bold;
color:#00FFD1;
}
.block-container{
padding-top:1rem;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<p class="main-title">🔐 Adaptive PQC Premium Dashboard</p>', unsafe_allow_html=True)

# -----------------------------------
# Refresh Button
# -----------------------------------
if st.button("🔄 Refresh Live Status"):
    st.rerun()

# -----------------------------------
# Device Status
# -----------------------------------
device = IoTDevice()
status = device.get_device_status()
decision = decide_execution(status)

battery = status["battery"]
cpu = status["cpu"]
memory = status["memory"]
network = status["network"]

kem = decision["kem"]
signature = decision["signature"]
mode = decision["execution"]

# -----------------------------------
# Metrics
# -----------------------------------
c1,c2,c3,c4 = st.columns(4)
c1.metric("🔋 Battery", f"{battery}%")
c2.metric("🧠 CPU", f"{cpu}%")
c3.metric("💾 Memory", f"{memory}%")
c4.metric("📶 Network", network)

# -----------------------------------
# Decision
# -----------------------------------
left,right = st.columns(2)

with left:
    st.subheader("🧠 Decision Output")
    st.json(decision)

with right:
    st.subheader("🔐 Security Selection")
    st.write("Mode:", mode.upper())
    st.write("KEM:", kem)
    st.write("Signature:", signature)

# -----------------------------------
# Execute
# -----------------------------------
if st.button("▶ Execute Adaptive PQC"):

    if mode == "edge":
        payload = {
            "kem": kem,
            "signature": signature,
            "mode": mode
        }

        result = requests.post(EDGE_SERVER_URL, json=payload).json()

    else:
        start = time.time()

        kem_obj, pk = kyber_keygen()
        ct, ss1 = kyber_encrypt(kem_obj, pk)
        ss2 = kyber_decrypt(kem_obj, ct)

        end = time.time()

        result = {
            "status": "success",
            "kem_used": kem,
            "signature_used": signature,
            "mode": "local",
            "kem_success": ss1 == ss2,
            "execution_time_ms": round((end-start)*1000,2)
        }

    # Add resource snapshot
    result["battery"] = battery
    result["cpu"] = cpu
    result["memory"] = memory

    save_result(result)

    st.success("Execution Completed + Saved")
    st.json(result)

    st.rerun()

# -----------------------------------
# Analytics
# -----------------------------------
st.subheader("📊 Live Analytics")

files = glob.glob("results/*.json")
rows = []

for file in files:
    with open(file,"r") as f:
        try:
            rows.append(json.load(f))
        except:
            pass

if rows:

    df = pd.DataFrame(rows)

    a,b = st.columns(2)

    with a:
        st.write("### Local vs Edge")
        st.bar_chart(df["mode"].value_counts())

    with b:
        st.write("### KEM Usage")
        st.bar_chart(df["kem_used"].value_counts())

    c,d = st.columns(2)

    with c:
        st.write("### Signature Usage")
        st.bar_chart(df["signature_used"].value_counts())

    with d:
        st.write("### Avg Execution Time")
        st.bar_chart(df.groupby("mode")["execution_time_ms"].mean())

    st.write("### Execution Time Trend")
    st.line_chart(df["execution_time_ms"])

    st.write("### CPU Used Per Run")
    if "cpu" in df.columns:
        st.line_chart(df["cpu"])

    st.write("### Memory Used Per Run")
    if "memory" in df.columns:
        st.line_chart(df["memory"])

    st.write("### Battery Level Per Run")
    if "battery" in df.columns:
        st.line_chart(df["battery"])

else:
    st.info("No result logs yet.")