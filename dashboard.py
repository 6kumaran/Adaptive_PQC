import streamlit as st
import json, os, glob, requests, time
import pandas as pd
from datetime import datetime
from ml_decision_engine import ml_decide_execution
from iot_device import IoTDevice
import base64
from decision_engine import decide_execution
from pqc_module import (
    kem_keygen,
    kem_encrypt,
    kem_decrypt,
    encrypt_message,
    sign_payload
)
from multi_device_simulation import simulate_devices
from datetime import timedelta

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
    execution = decision["execution"]
    mode = decision["mode"]
    kem = decision["kem"]
    signature = decision["signature"]

    if execution == "edge":

        start = time.time()

        # Simulated edge execution
        time.sleep(0.005)

        end = time.time()

        result = {
            "status": "success",
            "execution_time_ms": round((end-start)*1000,2),
            "execution": "edge"
        }

    else:

        start = time.time()

        kem_obj, public_key = kem_keygen(kem)

        ciphertext, shared_secret = kem_encrypt(
            kem_obj,
            public_key
        )

        end = time.time()

        result = {
            "status": "success",
            "execution_time_ms":
                round((end-start)*1000,2),
            "kem_success": True,
            "execution": "local"
        }

    result["battery"] = battery
    result["cpu"] = cpu
    result["memory"] = memory

    result["mode"] = mode
    result["kem_used"] = kem
    result["signature_used"] = signature
    # Threat-Aware Fields

    result["threat_profile"] = decision.get(
    "threat_profile",
    "UNKNOWN"
    )

    result["threat_score"] = decision.get(
    "threat_score",
    0
    )

    result["threat_level"] = decision.get(
    "threat_level",
    "SAFE"
    )

    result["threat_override"] = decision.get(
    "threat_override",
    False
    )

    return result

EDGE_SERVER_URL = "http://127.0.0.1:8000/offload"
RESULTS_FOLDER = "results"
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# -----------------------------------
# Save Result
# -----------------------------------
def save_result(data):

    data["timestamp"] = datetime.now().isoformat()

    filename = datetime.now().strftime("%Y%m%d_%H%M%S.json")
    filepath = os.path.join(RESULTS_FOLDER, filename)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

def save_simulation_results(results):

    base_time = datetime.now()

    for i, row in enumerate(results):

        row["timestamp"] = (
            base_time +
            timedelta(seconds=i)
        ).isoformat()

        row["record_type"] = "simulation"
        row["record_type"] = "simulation"

    filename = datetime.now().strftime(
        "simulation_%Y%m%d_%H%M%S.json"
    )

    filepath = os.path.join(
        RESULTS_FOLDER,
        filename
    )

    with open(filepath, "w") as f:
        json.dump(results, f, indent=4)
        
def display_decision(decision):
    st.markdown(f"""
    **Execution:** {decision['execution'].upper()}  
    **Mode:** {decision['mode']}  
    **KEM:** {decision['kem']}  
    **Signature:** {decision['signature']}
    """)

def secure_channel_demo(
        message,
        decision):

    kem = decision["kem"]
    signature = decision["signature"]

    start = time.time()

    try:

        kem_obj, public_key = kem_keygen(kem)

        ciphertext, shared_secret = kem_encrypt(
            kem_obj,
            public_key
        )

        encrypted_payload = encrypt_message(
            shared_secret,
            message
        )

        signature_data = sign_payload(
            signature,
            encrypted_payload["ciphertext"].encode()
        )

        payload = {
            "kem": kem,
            "ciphertext":
                encrypted_payload["ciphertext"],
            "nonce":
                encrypted_payload["nonce"],
            "shared_secret":
                base64.b64encode(
                    shared_secret
                ).decode(),

            "signature_algorithm":
                signature,

            "signature":
                signature_data["signature"],

            "public_key":
                signature_data["public_key"]
        }

        response = requests.post(
            EDGE_SERVER_URL,
            json=payload,
            timeout=10
        )

        result = response.json()

        end = time.time()

        return {
            "status": "success",
            "record_type": "secure_channel",
            "kem": kem,
            "signature": signature,

            "ciphertext":
                encrypted_payload["ciphertext"],

            "ciphertext_size":
                len(
                    encrypted_payload[
                        "ciphertext"
                    ]
                ),

            "signature_size":
                len(
                    signature_data[
                        "signature"
                    ]
                ),

            "execution_time_ms":
                round(
                    (end-start)*1000,
                    2
                ),

            "response": result
        }

    except Exception as e:

        return {
            "status": "failed",
            "error": str(e)
        }
    
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
threat_profile = st.selectbox(
    "🛡 Threat Profile",
    [
        "AUTO",
        "SAFE",
        "LOW",
        "MEDIUM",
        "HIGH"
    ]
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
rule_decision = decide_execution(
    status,
    threat_profile
)
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
# Threat Monitor
# -----------------------------------
st.markdown("---")
st.subheader("🛡 Threat Monitor")

t1, t2 = st.columns(2)
st.info(
    f"Current Threat Profile: "
    f"{decision.get('threat_profile', 'AUTO')}"
)
if decision.get("threat_override", False):

    st.error(
        "⚠ Threat Override Active "
        "- Security Elevated"
    )

with t1:

    st.metric(
        "Threat Score",
        decision.get(
            "threat_score",
            0
        )
    )

with t2:

    st.metric(
        "Threat Level",
        decision.get(
            "threat_level",
            "SAFE"
        )
    )

indicators = decision.get(
    "threat_indicators",
    []
)

if indicators:

    st.warning(
        "Active Threat Indicators"
    )

    for item in indicators:
        st.write("⚠️", item)

else:

    st.success(
        "No Threat Indicators Detected"
    )

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
        **Status:** {rule_result.get('status', 'unknown')} 
        """)

        with st.expander("🔍 Details"):
            st.json(rule_result)

    with col2:
        st.caption("ML-Based")

        st.markdown(f"""
        **Time:** {ml_result['execution_time_ms']} ms  
        **Status:** {ml_result.get('status', 'unknown')}  
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
    result["record_type"] = "execution"
    save_result(result)

st.markdown("---")
st.subheader("🔐 Live Secure Communication Demo")

secure_message = st.text_area(
    "Message To Protect",
    "Patient Heart Rate = 92 BPM"
)

secure_demo = st.button(
    "🚀 Send Secure Message",
    key="secure_demo"
)

if secure_demo:

    result = secure_channel_demo(
        secure_message,
        decision
    )

    if result["status"] == "success":

        st.success(
            "Secure Transmission Complete"
        )

        c1, c2 = st.columns(2)

        with c1:

            st.metric(
                "Ciphertext Size",
                result["ciphertext_size"]
            )

            st.metric(
                "Execution Time (ms)",
                result["execution_time_ms"]
            )

        with c2:

            st.metric(
                "Signature Size",
                result["signature_size"]
            )

            st.metric(
                "Verification",
                "SUCCESS"
                if result["response"].get(
                    "signature_verified"
                )
                else "FAILED"
            )

        st.markdown(
            f"**Selected KEM:** "
            f"{result['kem']}"
        )

        st.markdown(
            f"**Selected Signature:** "
            f"{result['signature']}"
        )

        st.markdown(
            "**Encrypted Payload:**"
        )

        st.code(
            result["ciphertext"][:120]
            + "..."
        )

        st.markdown(
            "**Recovered Message:**"
        )

        st.success(
            result["response"].get(
                "decrypted_message",
                "N/A"
            )
        )

    else:

        st.error(
            result["error"]
        )
# -----------------------------------
# Multi-Device Simulation
# -----------------------------------
st.markdown("---")
st.subheader("🌐 Multi-Device Simulation")
if st.button("📈 Generate 500 Demo Runs"):

    all_results = []

    for _ in range(50):

        batch = simulate_devices(
            10,
            use_ml=False
        )

        all_results.extend(batch)

    save_simulation_results(all_results)

    st.success(
        f"{len(all_results)} records generated"
    )

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

        analytics_view = st.selectbox(
            "Analytics View",
            [
            "All Records",
            "Simulation",
            "Execution",
            "Secure Channel"
            ]
        )

        if (
            analytics_view == "Simulation"
            and "record_type" in df.columns
        ):
            df = df[
                df["record_type"] == "simulation"
            ]

        elif (
            analytics_view == "Execution"
            and "record_type" in df.columns
        ):
            df = df[
                df["record_type"] == "execution"
            ]

        elif (
            analytics_view == "Secure Channel"
            and "record_type" in df.columns
        ):
            df = df[
                df["record_type"] == "secure_channel"
            ]

        if "timestamp" in df.columns:

            df["timestamp"] = pd.to_datetime(
                df["timestamp"]
            )

            df = df.sort_values(
                "timestamp"
            )

        df = df.reset_index(drop=True)

        df["run_id"] = range(
            1,
            len(df) + 1
        )

        if len(df) > 500:
            df = df.tail(500)

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

            if "signature_used" in df.columns:
                st.bar_chart(
                    df["signature_used"].value_counts()
                )

        with d:
            st.caption("Avg Execution Time")
            st.bar_chart(df.groupby("mode")["execution_time_ms"].mean())
            
        if "timestamp" in df.columns:

            df["timestamp"] = pd.to_datetime(
                df["timestamp"]
            )

            df = df.sort_values(
                "timestamp"
            )

        st.caption("Execution Time Trend")

        if (
            "execution_time_ms" in df.columns
            and "timestamp" in df.columns
        ):

            trend_df = df.dropna(
                subset=["execution_time_ms"]
            ).copy()

            trend_df["rolling_avg"] = (
                trend_df["execution_time_ms"]
                .rolling(
                    window=20,
                    min_periods=1
                )
                .mean()
            )
            st.write(
            trend_df[
                ["timestamp", "execution_time_ms"]
            ].head(20)
            )
            trend_df = trend_df.set_index(
                "run_id"
            )

            st.line_chart(
                trend_df[
                    [
                        "execution_time_ms",
                        "rolling_avg"
                    ]
                ]
            )

        st.caption("CPU Used Per Run")
        if "cpu" in df.columns:

            cpu_df = df.dropna(
                subset=["cpu"]
            )

            if not cpu_df.empty:

                cpu_df = cpu_df.set_index(
                    "run_id"
                )

                st.line_chart(
                    cpu_df["cpu"]
                )

        st.caption("Memory Used Per Run")
        if "memory" in df.columns:
            mem_df = df.dropna(
                subset=["memory"]
            )

            if not mem_df.empty:

                mem_df = mem_df.set_index(
                    "run_id"
                )

                st.line_chart(
                    mem_df["memory"]
                )

        st.caption("Battery Level Per Run")
        if "battery" in df.columns:
            batt_df = df.dropna(
                subset=["battery"]
            )

            if not batt_df.empty:

                batt_df = batt_df.set_index(
                    "timestamp"
                )

                st.line_chart(
                    batt_df["battery"]
                )
        st.markdown("---")
        st.subheader("🛡 Threat Analytics")
        valid_modes = [
            "performance",
            "balanced",
            "high_security"
        ]

        threat_df = df.copy()

        if "mode" in threat_df.columns:
            threat_df = threat_df[
                threat_df["mode"].isin(valid_modes)
            ]
        if "threat_level" in threat_df.columns:

            st.caption("Threat Level Distribution")

            st.bar_chart(
                threat_df[
                    "threat_level"
                ].value_counts()
            )
        if "threat_score" in threat_df.columns:

            st.caption("Threat Score Trend")

            score_df = threat_df.dropna(
                subset=["threat_score"]
            )

            if not score_df.empty:

                score_df = score_df.set_index(
                    "run_id"
                )

                st.line_chart(
                    score_df["threat_score"]
                )
        if "threat_override" in threat_df.columns:

            st.caption(
                "Threat Override Statistics"
            )

            override_counts = (
                threat_df[
                    "threat_override"
                ]
                .astype(str)
                .value_counts()
            )

            st.bar_chart(
                override_counts
            )
        if (
            "threat_level" in threat_df.columns
            and
            "mode" in threat_df.columns
        ):

            st.caption(
                "Threat Level vs Security Mode"
            )

            threat_mode = pd.crosstab(
                threat_df["threat_level"],
                threat_df["mode"]
            )

            st.bar_chart(
                threat_mode
            )
        if (
            "threat_level" in threat_df.columns
            and
            "kem_used" in threat_df.columns
        ):  

            st.caption(
                "Threat Level vs KEM Selection"
            )

            threat_kem = pd.crosstab(
                threat_df["threat_level"],
                threat_df["kem_used"]
            )

            st.bar_chart(
                threat_kem
            )
    else:
        st.info("No result logs yet.")