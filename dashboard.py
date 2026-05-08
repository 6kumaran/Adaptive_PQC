import streamlit as st
import json, os, glob, requests, time
import pandas as pd
from datetime import datetime
from ml_decision_engine import ml_decide_execution
from iot_device import IoTDevice
from decision_engine import decide_execution
from pqc_module import kyber_keygen, kyber_encrypt, kyber_decrypt
from multi_device_simulation import simulate_devices

def generate_explanation(status, decision):

    battery = status["battery"]
    cpu = status["cpu"]
    memory = status["memory"]
    network = status["network"]

    explanation = []

    # Battery
    if battery > 70:
        explanation.append("🔋 High battery → supports local execution")
    elif battery > 40:
        explanation.append("🔋 Moderate battery → balanced decision")
    else:
        explanation.append("🔋 Low battery → prefers edge offloading")

    # CPU
    if cpu < 40:
        explanation.append("🧠 Low CPU usage → local execution efficient")
    elif cpu < 75:
        explanation.append("🧠 Moderate CPU → balanced decision")
    else:
        explanation.append("🧠 High CPU load → offloading preferred")

    # Memory
    if memory < 50:
        explanation.append("💾 Low memory usage → local possible")
    elif memory < 75:
        explanation.append("💾 Moderate memory → balanced")
    else:
        explanation.append("💾 High memory usage → edge preferred")

    # Network
    if network == "good":
        explanation.append("📶 Good network → edge execution feasible")
    elif network == "moderate":
        explanation.append("📶 Moderate network → mixed decision")
    else:
        explanation.append("📶 Poor network → local preferred")

    # Final decision summary
    explanation.append(f"⚙️ Final Decision → {decision['execution'].upper()} mode with {decision['mode']} security")

    return explanation

def run_execution(decision, battery, cpu, memory):
    mode = decision["execution"]
    kem = decision["kem"]
    signature = decision["signature"]

    if mode == "edge":
        payload = {
            "kem": kem,
            "signature": signature,
            "mode": mode
        }

        try:
            start = time.time()
            response = requests.post(EDGE_SERVER_URL, json=payload, timeout=5)
            result = response.json()
            end = time.time()
            result["execution_time_ms"] = round((end-start)*1000,2)
        except:
            result = {"status": "failed", "execution_time_ms": None}

    else:
        start = time.time()

        kem_obj, pk = kyber_keygen()
        ct, ss1 = kyber_encrypt(kem_obj, pk)
        ss2 = kyber_decrypt(kem_obj, ct)

        end = time.time()

        result = {
            "status": "success",
            "execution_time_ms": round((end-start)*1000,2),
            "kem_success": ss1 == ss2
        }

    result["battery"] = battery
    result["cpu"] = cpu
    result["memory"] = memory

    return result

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

def save_simulation_results(results):

    filename = datetime.now().strftime("simulation_%Y%m%d_%H%M%S.json")
    filepath = os.path.join(RESULTS_FOLDER, filename)

    with open(filepath, "w") as f:
        json.dump(results, f, indent=4)
        
def display_decision(decision):
    st.markdown(f"""
    **Execution:** {decision['execution'].upper()}  
    **Mode:** {decision['mode']}  
    **KEM:** {decision['kem']}  
    **Signature:** {decision['signature']}
    """)

# -----------------------------------
# Premium UI
# -----------------------------------
st.set_page_config(page_title="Adaptive PQC Dashboard", layout="wide")

st.markdown("""
<style>
.main-title{
padding-top:1rem;
font-size:32px;
font-weight:bold;
color:#00FFD1;
text-align:center;
}
.block-container{
padding-top:1rem;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<p class="main-title">🔐 Adaptive PQC Premium Dashboard</p>', unsafe_allow_html=True)

# -----------------------------------
# Decision Mode Toggle
# -----------------------------------
decision_mode = st.radio(
    "⚙️ Select Decision Engine",
    ["Rule-Based", "ML-Based", "Compare Both"],
    horizontal=True
)

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
# -----------------------------------
# Decision Selection
# -----------------------------------
rule_decision = decide_execution(status)
ml_decision = ml_decide_execution(status)

if decision_mode == "Rule-Based":
    decision = rule_decision
elif decision_mode == "ML-Based":
    decision = ml_decision
else:
    decision = rule_decision  # default for execution

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
    st.subheader("🧠 Decision")

    if decision_mode == "Compare Both":
        col1, col2 = st.columns(2)

        with col1:
            st.caption("Rule-Based")
            display_decision(rule_decision)

        with col2:
            st.caption("ML-Based")
            display_decision(ml_decision)

    else:
        display_decision(decision)

    with st.expander("🔍 View Raw Data"):
        if decision_mode == "Compare Both":
            st.json({"rule": rule_decision, "ml": ml_decision})
        else:
            st.json(decision)

with right:
    st.subheader("🔐 Selection")
    st.markdown(f"""
    **Engine:** {decision_mode}  
    **Mode:** {mode.upper()}  
    **KEM:** {kem}  
    **Signature:** {signature}
    """)

execute_clicked = st.button("▶ Execute Adaptive PQC", key="execute_main")

# -----------------------------------
# Execute
# -----------------------------------
if execute_clicked:

    st.subheader("⚡ Performance Comparison")

    # Run both engines
    rule_result = run_execution(rule_decision, battery, cpu, memory)
    ml_result = run_execution(ml_decision, battery, cpu, memory)

    col1, col2 = st.columns(2)

    with col1:
        st.caption("Rule-Based")

        st.markdown(f"""
        **Time:** {rule_result['execution_time_ms']} ms  
        **Status:** {rule_result['status']}  
        """)

        with st.expander("🔍 Details"):
            st.json(rule_result)

    with col2:
        st.caption("ML-Based")

        st.markdown(f"""
        **Time:** {ml_result['execution_time_ms']} ms  
        **Status:** {ml_result['status']}  
        """)

        with st.expander("🔍 Details"):
            st.json(ml_result)

    # Compare
    try:
        rule_time = rule_result["execution_time_ms"]
        ml_time = ml_result["execution_time_ms"]

        if rule_time and ml_time:
            diff = round(abs(rule_time - ml_time), 2)

            if rule_time < ml_time:
                st.success(f"🏆 Rule-Based is faster by {diff} ms")
            elif ml_time < rule_time:
                st.success(f"🏆 ML-Based is faster by {diff} ms")
            else:
                st.info("⚖️ Both have equal performance")

    except:
        st.warning("⚠️ Could not compare (Edge server may be down)")

    # Save result
    result = ml_result if decision_mode == "ML-Based" else rule_result
    result["engine"] = decision_mode
    save_result(result)

# -----------------------------------
# Multi-Device Simulation
# -----------------------------------
st.markdown("---")
st.subheader("🌐 Multi-Device Simulation")

col1, col2 = st.columns(2)

with col1:
    num_devices = st.slider("Number of Devices", 1, 50, 10)

with col2:
    sim_mode = st.selectbox(
        "Decision Engine",
        ["Rule-Based", "ML-Based"]
    )

run_sim = st.button("🚀 Run Simulation", key="multi_sim")

if run_sim:

    use_ml = True if sim_mode == "ML-Based" else False

    results = simulate_devices(num_devices, use_ml)

    save_simulation_results(results)

    df = pd.DataFrame(results)

    st.success(f"Simulation completed for {num_devices} devices")

    # -----------------------------------
    # Summary Metrics
    # -----------------------------------
    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric("Edge Executions", (df["mode"] == "edge").sum())

    with c2:
        st.metric("Local Executions", (df["mode"] == "local").sum())

    with c3:
        st.metric("Avg Time (ms)", round(df["execution_time_ms"].mean(), 2))

    # -----------------------------------
    # Charts
    # -----------------------------------
    st.markdown("### 📊 Distribution")

    a, b = st.columns(2)

    with a:
        st.caption("Execution Mode")
        st.bar_chart(df["mode"].value_counts())

    with b:
        st.caption("KEM Usage")
        st.bar_chart(df["kem_used"].value_counts())

    # -----------------------------------
    # Optional Detailed View
    # -----------------------------------
    with st.expander("🔍 View Detailed Results"):
        st.dataframe(df)

# -----------------------------------
# Analytics
# -----------------------------------
with st.expander("📊 Analytics", expanded=False):
    st.subheader("📊 Live Analytics")

    files = glob.glob("results/*.json")
    rows = []

    for file in files:
        with open(file,"r") as f:
            try:
                data = json.load(f)
                # If simulation file (list)
                if isinstance(data, list):
                    rows.extend(data)
                
                # If single execution (dict)
                elif isinstance(data, dict):
                    rows.append(data)
            except:
                pass

    if rows:

        df = pd.DataFrame(rows)

        a,b = st.columns(2)

        with a:
            st.caption("Local vs Edge")
            st.bar_chart(df["mode"].value_counts())

        with b:
            st.caption("KEM Usage")
            st.bar_chart(df["kem_used"].value_counts())

        c,d = st.columns(2)

        with c:
            st.caption("Signature Usage")
            st.bar_chart(df["signature_used"].value_counts())

        with d:
            st.caption("Avg Execution Time")
            st.bar_chart(df.groupby("mode")["execution_time_ms"].mean())

        st.caption("Execution Time Trend")
        st.line_chart(df["execution_time_ms"])

        st.caption("CPU Used Per Run")
        if "cpu" in df.columns:
            st.line_chart(df["cpu"])

        st.caption("Memory Used Per Run")
        if "memory" in df.columns:
            st.line_chart(df["memory"])

        st.caption("Battery Level Per Run")
        if "battery" in df.columns:
            st.line_chart(df["battery"])

    else:
        st.info("No result logs yet.")