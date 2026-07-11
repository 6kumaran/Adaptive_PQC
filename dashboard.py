import streamlit as st
import json, os, glob, time
import copy
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime
from ml_decision_engine import ml_decide_execution
from iot_device import IoTDevice
from decision_engine import (
    decide_execution,
    assess_threat
)
from quantum_readiness import calculate_quantum_readiness
from secure_channel import (
    send_secure_message,
    SecurityTestMode
)
from multi_device_simulation import simulate_devices
from datetime import timedelta
from pqc_module import (
    kem_keygen,
    kem_encrypt,
    kem_decrypt
)
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
    result["security_strategy"] = decision["security_strategy"]
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
    result["context_profile"] = decision.get(
        "context_profile",
        "BALANCED"
    )

    result["context_priority"] = decision.get(
        "context_priority",
        "BALANCED"
    )

    result["context_description"] = decision.get(
        "context_description",
        ""
    )
    result.update({
    "estimated_energy":
        decision.get("estimated_energy"),

    "cpu_energy":
        decision.get("cpu_energy"),

    "memory_energy":
        decision.get("memory_energy"),

    "crypto_energy":
        decision.get("crypto_energy"),

    "signature_energy":
        decision.get("signature_energy"),

    "communication_energy":
        decision.get("communication_energy"),

    "energy_level":
        decision.get("energy_level"),
    "predicted_latency_ms":
        decision.get("predicted_latency_ms"),

    "latency_category":
        decision.get("latency_category"),
    "latency_optimization":
        decision.get("latency_optimization"),

    "latency_reason":
        decision.get("latency_reason"),
    })
    # ----------------------------------------
    # Quantum Readiness Assessment
    # ----------------------------------------

    assessment = calculate_quantum_readiness(result)

    result.update(assessment)
    return result

def apply_protocol_threat_events(threat_score, threat_indicators, secure_result):
    """
    Updates the threat score and indicators based on
    secure communication protocol events.
    """
    if not secure_result:
        return threat_score, threat_indicators
    response = secure_result.get("response", {})
    # Replay Attack
    if response.get("replay_detected", False):
        threat_score += 20
        if "Replay Attack Indicator" not in threat_indicators:
            threat_indicators.append("Replay Attack Indicator")
    # Expired Message
    if response.get("expired", False):
        threat_score += 10
        if "Expired Message" not in threat_indicators:
            threat_indicators.append("Expired Message")
    # Signature Verification Failure
    if response.get("signature_verified") is False:
        threat_score += 30
        if "Signature Verification Failure" not in threat_indicators:
            threat_indicators.append("Signature Verification Failure")
    # Prevent overflow
    threat_score = min(threat_score, 100)
    return threat_score, threat_indicators

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
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(
            "Execution",
            decision["execution"].upper()
        )
    with col2:
        st.metric(
            "Strategy",
            decision["security_strategy"]
        )
    with col3:
        st.metric(
            "Mode",
            decision["mode"].replace("_", " ").title()
        )
    col4, col5 = st.columns(2)
    with col4:
        st.metric(
            "KEM",
            decision["kem"]
        )
    with col5:
        st.metric(
            "Signature",
            decision["signature"]
        )
    if decision["security_strategy"] == "HYBRID":
        st.success("Classical Signature: ECDSA-P256")
# -----------------------------------
# Premium UI
# -----------------------------------
st.set_page_config(
    page_title="Adaptive Secure Edge–Cloud PQC Framework",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>

/* ---------- Main Layout ---------- */

.block-container{
    padding-top:1.2rem;
    padding-bottom:2rem;
}

/* ---------- Main Title ---------- */

.main-title{
    font-size:36px;
    font-weight:700;
    color:#00FFD1;
    text-align:center;
    margin-bottom:0.2rem;
}

.sub-title{
    text-align:center;
    color:#A8B2C1;
    font-size:16px;
    margin-bottom:2rem;
}

/* ---------- Section Headers ---------- */

.section-title{
    font-size:24px;
    font-weight:600;
    color:#FFFFFF;
    padding-top:0.5rem;
    padding-bottom:0.6rem;
    border-bottom:2px solid #00FFD1;
    margin-top:1.2rem;
    margin-bottom:1rem;
}

/* ---------- Streamlit Metric Cards ---------- */

div[data-testid="stMetric"]{
    background-color:#1B1F2A;
    border:1px solid #2C3240;
    border-radius:14px;
    padding:15px;
    transition:0.3s;
}

div[data-testid="stMetric"]:hover{
    border-color:#00FFD1;
    transform:translateY(-2px);
}

/* ---------- Buttons ---------- */

.stButton>button{
    border-radius:10px;
    font-weight:600;
    height:42px;
}

/* ---------- Expanders ---------- */

details{
    border-radius:10px;
}

</style>
""", unsafe_allow_html=True)

st.markdown(
"""
<div class="main-title">
Adaptive Secure Edge–Cloud Post-Quantum Cryptography Framework
</div>

<div class="sub-title">
Research Prototype Dashboard
</div>
""",
unsafe_allow_html=True
)
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
context_profile = st.selectbox(
    "🏷 Application Context",
    [
        "BALANCED",
        "HIGH_SECURITY",
        "PERFORMANCE",
        "ENERGY_SAVING",
        "MISSION_CRITICAL"
    ]
)
st.markdown(
    '<div class="section-title">⚙️ Application Configuration</div>',
    unsafe_allow_html=True
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
# Shared Threat Assessment
# -----------------------------------
shared_threat = assess_threat(threat_profile)
# -----------------------------------
# Decision Selection
# -----------------------------------
rule_decision = decide_execution(
    status,
    threat_profile,
    threat_data=shared_threat,
    context_profile=context_profile
)
ml_decision = ml_decide_execution(
    status,
    threat_profile,
    threat_data=shared_threat,
    context_profile=context_profile
)
if decision_mode == "Rule-Based":
    decision = rule_decision
elif decision_mode == "ML-Based":
    decision = ml_decision
else:
    decision = rule_decision  # default for execution
# -----------------------------------
# Persist Current Decision
# -----------------------------------
if "current_decision" not in st.session_state:
    st.session_state.current_decision = decision

st.session_state.current_decision = decision
# -----------------------------------
# Sync Threat State
# -----------------------------------
st.session_state.threat_state = {
    "score": decision.get("threat_score", 0),
    "level": decision.get("threat_level", "SAFE"),
    "indicators": decision.get(
        "threat_indicators",
        []
    ).copy()
}
battery = status["battery"]
cpu = status["cpu"]
memory = status["memory"]
network = status["network"]
kem = decision["kem"]
signature = decision["signature"]
mode = decision["execution"]
# -----------------------------------
# Runtime Dashboard
# -----------------------------------

with st.container(border=True):

    st.markdown(
        "## 🖥 Runtime Dashboard"
    )

    st.caption(
        "Current IoT device status and adaptive security assessment."
    )

    st.markdown("### 💻 Live Device Status")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("🔋 Battery", f"{battery}%")

    with c2:
        st.metric("🧠 CPU", f"{cpu}%")

    with c3:
        st.metric("💾 Memory", f"{memory}%")

    with c4:
        st.metric("📶 Network", network)

    st.divider()

    st.markdown("### 🛡 Threat Monitor")

    top1, top2 = st.columns(2)

    with top1:
        st.metric(
            "Threat Profile",
            decision.get(
                "threat_profile",
                "AUTO"
            )
        )

    with top2:
        st.metric(
            "Context Profile",
            decision.get(
                "context_profile",
                "BALANCED"
            )
        )

    if decision.get("context_description"):
        st.caption(
            decision["context_description"]
        )

    t1, t2 = st.columns(2)

    with t1:
        st.metric(
            "Threat Score",
            st.session_state.threat_state["score"]
        )

    with t2:
        st.metric(
            "Threat Level",
            st.session_state.threat_state["level"]
        )

    if decision.get("threat_override", False):
        st.error(
            "⚠ Threat Override Active"
        )

    indicators = st.session_state.threat_state[
        "indicators"
    ]

    if indicators:

        st.warning(
            "Active Threat Indicators"
        )

        for indicator in indicators:
            st.write(
                f"⚠️ {indicator}"
            )

    else:

        st.success(
            "No Threat Indicators Detected"
        )
# -----------------------------------
# Adaptive Decision Dashboard
# -----------------------------------

with st.container(border=True):

    st.markdown("## 🧠 Adaptive Decision Engine")
    st.caption(
        "Adaptive cryptographic decision generated from the current device, threat, and context state."
    )
    # -----------------------------------
    # Decision
    # -----------------------------------
    # Single full-width Decision section
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
    st.markdown("---")
    if decision["security_strategy"] == "HYBRID":
        st.markdown("#### 🔐 Classical Security")

        st.info(
            "Classical Signature: ECDSA-P256 + PQC Signature"
        )
    execute_clicked = st.button(
        "🚀 Execute Adaptive PQC Framework",
        key="execute_main"
    )
# -----------------------------------
# Execute
# -----------------------------------
if execute_clicked:
    rule_result = run_execution(rule_decision, battery, cpu, memory)
    ml_result = run_execution(ml_decision, battery, cpu, memory)
    st.subheader("⚡ Performance Comparison")
    st.caption(
        "Energy consumption trends and resource-aware security analysis."
    )
    summary1, summary2, summary3 = st.columns(3)

    summary1.metric(
        "Rule Time",
        f"{rule_result['execution_time_ms']} ms"
    )
    
    summary2.metric(
        "ML Time",
        f"{ml_result['execution_time_ms']} ms"
    )
    
    summary3.metric(
        "Difference",
        f"{abs(rule_result['execution_time_ms'] - ml_result['execution_time_ms']):.2f} ms"
    )
    # Run both engines
    col1, col2 = st.columns(2)
    with col1:
        st.caption("Rule-Based")
        st.markdown(f"""
        **Time:** {rule_result['execution_time_ms']} ms  
        """)
        st.metric(
            "⚡ Estimated Energy",
            f"{rule_result['estimated_energy']:.2f}"
        )

        st.metric(
            "Energy Level",
            rule_result["energy_level"]
        )
        score = rule_result["quantum_readiness_score"]

        st.metric(
            "Quantum Readiness",
            f"{score}/100"
        )

        st.progress(score / 100)

        st.caption(
            f"Level: {rule_result['quantum_readiness_level']}"
        )
        with st.expander("🔍 Details"):

            st.markdown("### ✅ Recommendations")
        
            for rec in rule_result["recommendations"]:
                st.success(rec)
        
            st.markdown("---")
        
            st.markdown("### Raw Execution Result")
        
            st.json(rule_result)
    with col2:
        st.caption("ML-Based")
        st.markdown(f"""
        **Time:** {ml_result['execution_time_ms']} ms  
        """)
        st.metric(
            "⚡ Estimated Energy",
            f"{ml_result['estimated_energy']:.2f}"
        )

        st.metric(
            "Energy Level",
            ml_result["energy_level"]
        )
        score = ml_result["quantum_readiness_score"]

        st.metric(
            "Quantum Readiness",
            f"{score}/100"
        )

        st.progress(score / 100)

        st.caption(
            f"Level: {ml_result['quantum_readiness_level']}"
        )
        with st.expander("🔍 Details"):

            st.markdown("### ✅ Recommendations")
        
            for rec in ml_result["recommendations"]:
                st.success(rec)
        
            st.markdown("---")
        
            st.markdown("### Raw Execution Result")
        
            st.json(ml_result)

    # Compare
    try:
        rule_time = rule_result["execution_time_ms"]
        ml_time = ml_result["execution_time_ms"]
        if rule_time and ml_time:
            diff = round(abs(rule_time - ml_time), 2)
            st.markdown("---")

            winner_col1 = st.container()

            with winner_col1:
            
                if rule_time < ml_time:
                
                    st.success(
                        f"🏆 Winner: Rule-Based ({diff} ms faster)"
                    )

                elif ml_time < rule_time:
                
                    st.success(
                        f"🏆 Winner: ML-Based ({diff} ms faster)"
                    )

                else:
                
                    st.info(
                        "⚖ Both engines performed equally."
                    )

            with winner_col2:
            
                st.metric(
                    "Difference",
                    f"{diff} ms"
                )
    except:
        st.warning("⚠️ Could not compare (Edge server may be down)")
    # Save result
    result = ml_result if decision_mode == "ML-Based" else rule_result
    result["engine"] = decision_mode
    result["record_type"] = "execution"
    save_result(result)
st.markdown("---")
with st.container(border=True):

    st.markdown("## 🔐 Secure Communication")

    st.caption(
        "Encrypt, transmit, verify, and validate secure messages using the adaptive PQC framework."
    )
    secure_message = st.text_area(
        "Message To Protect",
        "Patient Heart Rate = 92 BPM"
    )

    col1, col2 = st.columns([2, 1])

    with col1:
        security_test = st.selectbox(
            "🧪 Security Test",
            [
                SecurityTestMode.NORMAL,
                SecurityTestMode.REPLAY,
                SecurityTestMode.EXPIRED,
                SecurityTestMode.TAMPERED
            ],
            index=0
        )

    with col2:
        st.write("")      # spacing
        st.write("")

        secure_demo = st.button(
            "🚀 Send Secure Message",
            key="secure_demo",
            use_container_width=True
        )
if secure_demo:
    result = send_secure_message(
        secure_message,
        st.session_state.current_decision,
        security_test
    )
    score, indicators = apply_protocol_threat_events(
        st.session_state.threat_state["score"],
        st.session_state.threat_state["indicators"],
        result
    )
    st.session_state.threat_state["score"] = score
    st.session_state.threat_state["indicators"] = indicators
    if "threat_state" not in st.session_state:
        st.session_state.threat_state = {
            "score": decision.get("threat_score", 0),
            "level": decision.get("threat_level", "SAFE"),
            "indicators": decision.get(
                "threat_indicators",
                []
            ).copy()
        }
    score = st.session_state.threat_state["score"]
    if score >= 80:
        st.session_state.threat_state["level"] = "HIGH"
    elif score >= 50:
        st.session_state.threat_state["level"] = "MEDIUM"
    elif score >= 20:
        st.session_state.threat_state["level"] = "LOW"
    else:
        st.session_state.threat_state["level"] = "SAFE"
    if result["status"] == "success":
        st.success(
            "✅ Secure Transmission Complete"
        )
        st.markdown("### Transmission Result")
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
        st.markdown("### Cryptography")

        k1, k2, k3 = st.columns(3)

        with k1:
            st.metric(
                "Strategy",
                result["security_strategy"]
            )

        with k2:
            st.metric(
                "KEM",
                result["kem"]
            )

        with k3:
            st.metric(
                "Signature",
                result["signature"]
            )
        if result["security_strategy"] == "HYBRID":
            st.markdown(
                "**Classical Signature:** ECDSA-P256"
            )
        with st.expander("Encrypted Payload"):

            st.code(
                result["ciphertext"][:120] + "..."
            )
        st.markdown("### Recovered Message")

        st.success(
            result["response"].get(
                "decrypted_message",
                "N/A"
            )
        )
        secure_log = {
            "record_type": "secure_channel",
            "protocol_version": "2.0",
            "timestamp": datetime.now().isoformat(),
            "kem_used": result["kem"],
            "signature_used": result["signature"],
            "execution_time_ms":
            result["execution_time_ms"],
            "ciphertext_size":
            result["ciphertext_size"],
            "signature_size":
            result["signature_size"],
            "security": {
                "strategy": decision["security_strategy"],
                "mode": decision["mode"],
                "kem": decision["kem"],
                "signature": decision["signature"]
            },
            "status":
            result["response"].get("status"),
            "signature_verified":
            result["response"].get("signature_verified"),
            "context_profile":
            decision.get("context_profile"),

            "context_priority":
            decision.get("context_priority"),

            "context_description":
            decision.get("context_description"),
            }
        save_result(secure_log)
    else:

        st.error(
            result["error"]
        )
    st.markdown("---")
    st.subheader("🛡 Protocol Validation Result")
    response = result["response"]
    if response.get("status") == "success":
        st.success("✅ Secure packet accepted")
    else:
        st.error(f"❌ {response.get('message','Unknown Error')}")
    if response.get("replay_detected"):
        st.warning("🔁 Replay attack detected")
    if response.get("expired"):
        st.warning("⏰ Packet expired")
    if response.get("signature_verified") is False:
        st.warning("📝 Signature verification failed")
    # -----------------------------------
    # Replay Analytics
    # -----------------------------------
    if "security_stats" not in st.session_state:
        st.session_state.security_stats = {
        "success": 0,
        "replay": 0,
        "expired": 0,
        "tampered": 0
        }
    response = result["response"]
    if response.get("status") == "success":
        st.session_state.security_stats["success"] += 1
    elif response.get("replay_detected"):
        st.session_state.security_stats["replay"] += 1
    elif response.get("expired"):
        st.session_state.security_stats["expired"] += 1
    elif response.get("signature_verified") is False:
        st.session_state.security_stats["tampered"] += 1
    st.markdown("---")
    st.subheader("📊 Replay Protection Analytics")
    stats = st.session_state.security_stats
    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
    "✅ Successful",
    stats["success"]
    )
    c2.metric(
    "🔁 Replay",
    stats["replay"]
    )
    c3.metric(
    "⏰ Expired",
    stats["expired"]
    )
    c4.metric(
    "📝 Tampered",
    stats["tampered"]
    )
# -----------------------------------
# Multi-Device Simulation
# -----------------------------------
st.markdown("---")

with st.container(border=True):

    st.markdown("## 🌐 Multi-Device Simulation")

    st.caption(
        "Simulate adaptive cryptographic decisions across multiple IoT devices."
    )
    
    st.markdown("### Simulation Configuration")

    cfg1, cfg2 = st.columns(2)

    with cfg1:
        num_devices = st.slider("Number of Devices", 1, 50, 10)

    with cfg2:
        sim_mode = st.selectbox(
            "Decision Engine",
            ["Rule-Based", "ML-Based"]
        )

    btn1, btn2 = st.columns(2)

    with btn1:
        if st.button("📈 Generate 500 Demo Runs"):
            all_results = []
            for _ in range(50):
                batch = simulate_devices(
                    10,
                    use_ml=False,
                    simulation_mode=True
                )
                all_results.extend(batch)
            save_simulation_results(all_results)
            st.success(
                f"{len(all_results)} records generated"
            )

    with btn2:
        run_sim = st.button(
            "🚀 Run Simulation",
            key="multi_sim"
        )
    if run_sim:
        use_ml = True if sim_mode == "ML-Based" else False
        results = simulate_devices(num_devices, use_ml,simulation_mode=True)
        save_simulation_results(results)
        df = pd.DataFrame(results)
        st.success(f"Simulation completed for {num_devices} devices")
        # -----------------------------------
        # Summary Metrics
        # -----------------------------------
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Devices Simulated", len(df))
        with c2:
            st.metric("Edge Executions", (df["execution"] == "edge").sum())
        with c3:
            st.metric("Local Executions", (df["execution"] == "local").sum())
        with c4:
            st.metric("Avg Execution Time (ms)", round(df["execution_time_ms"].mean(), 2))
        # -----------------------------------
        # Charts
        # -----------------------------------
        # -----------------------------------
        # Optional Detailed View
        # -----------------------------------
        with st.expander("📋 Device Simulation Results"):
            st.dataframe(df)
            for r in results:
                if r["execution"] == "edge":
                    st.json(r)
                    break
# -----------------------------------
# Analytics
# -----------------------------------
st.markdown(
    '<div class="section-title">📈 Analytics</div>',
    unsafe_allow_html=True
)
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
        MAX_HISTORY = 200

        if len(df) > MAX_HISTORY:
            df = df.tail(MAX_HISTORY)

            
        with st.container(border=True):

            st.markdown("## 🌐 Network Analytics")

            st.caption(
                "Latency trends, strategy comparison and optimization overview."
            )
            # -----------------------------------
            # Network Latency Analytics
            # -----------------------------------

            if "predicted_latency_ms" in df.columns:
            
                latency_df = df.dropna(
                    subset=["predicted_latency_ms"]
                )

                if not latency_df.empty:

                    l1, l2, l3 = st.columns(3)

                    with l1:
                        st.metric(
                            "Average Latency",
                            f"{latency_df['predicted_latency_ms'].mean():.2f} ms"
                        )

                    with l2:
                        st.metric(
                            "Peak Latency",
                            f"{latency_df['predicted_latency_ms'].max():.2f} ms"
                        )

                    with l3:
                        st.metric(
                            "Minimum Latency",
                            f"{latency_df['predicted_latency_ms'].min():.2f} ms"
                        )
            st.markdown("#### Predicted Latency Trend")

            if "predicted_latency_ms" in df.columns:
            
                latency_df = df.dropna(
                    subset=["predicted_latency_ms"]
                ).copy()

                if not latency_df.empty:
                
                    latency_df["rolling_avg"] = (
                        latency_df["predicted_latency_ms"]
                        .rolling(
                            window=20,
                            min_periods=1
                        )
                        .mean()
                    )

                    latency_df = latency_df.set_index(
                        "run_id"
                    )

                    st.line_chart(
                        latency_df[
                            [
                                "predicted_latency_ms",
                                "rolling_avg"
                            ]
                        ]
                    )
            # -----------------------------------
            # Average Latency by Security Strategy
            # -----------------------------------

            col1, col2 = st.columns(
                [1, 1],
                gap="small"
            )

            with col1:
            
                if (
                    "security_strategy" in latency_df.columns
                    and "predicted_latency_ms" in latency_df.columns
                ):

                    strategy_latency = (
                        latency_df.groupby(
                            "security_strategy"
                        )["predicted_latency_ms"]
                        .mean()
                        .reset_index()
                    )

                    fig = px.bar(
                        strategy_latency,
                        x="security_strategy",
                        y="predicted_latency_ms",
                        color="security_strategy",
                        title="Latency by Security Strategy"
                    )
                    fig.update_layout(
                        height=320,

                        font=dict(
                            size=15
                        ),

                        title_font=dict(
                            size=20
                        ),

                        xaxis=dict(
                            tickfont=dict(size=13),
                            title_font=dict(size=15)
                        ),

                        yaxis=dict(
                            tickfont=dict(size=13),
                            title_font=dict(size=15)
                        ),

                        margin=dict(
                            l=20,
                            r=20,
                            t=40,
                            b=20
                        ),
                        legend_title_text=None,

                        legend=dict(
                            font=dict(size=13),
                            orientation="h",
                            y=-0.25,
                            x=0.5,
                            xanchor="center"
                        )
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        key="latency_strategy_chart",
                    )

            with col2:
            
                if "latency_optimization" in latency_df.columns:

                    optimization_counts = (
                        latency_df["latency_optimization"]
                        .map({
                            True: "Optimized",
                            False: "Not Optimized"
                        })
                        .value_counts()
                        .reset_index()
                    )
                    
                    optimization_counts.columns = [
                        "Optimization",
                        "Count",
                    ]

                    fig = px.pie(
                        optimization_counts,
                        names="Optimization",
                        values="Count",
                        hole=0.60,
                        title="Latency Optimization Distribution"
                    )

                    fig.update_traces(
                        textposition="inside",
                        textinfo="percent+label"
                    )

                    fig.update_layout(
                        height=320,
                        margin=dict(
                            l=20,
                            r=20,
                            t=40,
                            b=20,
                        ),
                        showlegend=True,
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        key="latency_optimization_chart",
                    )
        # -----------------------------------
        # Multi-Edge Load Balancing Analytics
        # -----------------------------------

        if "selected_edge" in df.columns:
        
            edge_df = df.dropna(
                subset=["selected_edge"]
            )

            if not edge_df.empty:
            
                st.subheader(
                    "🌍 Multi-Edge Load Balancing Analytics"
                )
                st.caption(
                    "Edge selection, workload distribution and resource utilization."
                )

                c1, c2, c3 = st.columns(3)

                with c1:
                    st.metric(
                        "Edge Executions",
                        len(edge_df)
                    )

                with c2:
                    st.metric(
                        "Average Edge Latency",
                        f"{edge_df['edge_latency'].mean():.2f} ms"
                    )

                with c3:
                    st.metric(
                        "Average Edge Load",
                        f"{edge_df['edge_load'].mean():.2f}"
                    )
            col1, col2 = st.columns([1, 1], gap="small")
            with col1:
                if not edge_df.empty:

                    selected_edge_counts = (
                        edge_df["selected_edge"]
                        .value_counts()
                        .reset_index(name="Count")
                        .rename(columns={"selected_edge": "Selected Edge"})
                    )

                    fig = px.bar(
                        selected_edge_counts,
                        x="Selected Edge",
                        y="Count",
                        color="Selected Edge",
                        title="Selected Edge Distribution"
                    )
                    fig.update_layout(
                        height=300,
                        showlegend=False,
                        margin=dict(
                            l=20,
                            r=20,
                            t=40,
                            b=20,
                        )
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        key="selected_edge_distribution",
                    )
            with col2:

                status_counts = (
                    edge_df["edge_status"]
                    .value_counts()
                    .reset_index(name="Count")
                    .rename(columns={"edge_status": "Status"})
                )

                fig = px.bar(
                    status_counts,
                    x="Status",
                    y="Count",
                    color="Status",
                    title="Edge Status Distribution"
                )
                fig.update_layout(
                    height=300,
                    showlegend=False,
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    )
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    key="edge_status_distribution",
                )
            st.markdown("#### Average Selected Edge Resources")
            resource_df = pd.DataFrame({
                "Metric": [
                    "CPU",
                    "Memory",
                    "Latency",
                    "Load"
                ],
                "Value": [
                    edge_df["edge_cpu"].mean(),
                    edge_df["edge_memory"].mean(),
                    edge_df["edge_latency"].mean(),
                    edge_df["edge_load"].mean() * 100
                ]
            })
            fig = px.bar(
                resource_df,
                x="Metric",
                y="Value",
                color="Metric",
            )
            fig.update_layout(
                height=320,
                showlegend=False,
                margin=dict(
                    l=20,
                    r=20,
                    t=40,
                    b=20
                )
            )
            st.plotly_chart(
                fig,
                use_container_width=True,
                key="edge_resource_summary",
            )
        # -----------------------------------
        # Quantum Readiness Analytics
        # -----------------------------------

        if "quantum_readiness_score" in df.columns:
        
            qr_df = df.dropna(
                subset=["quantum_readiness_score"]
            ).copy()

            if not qr_df.empty:
            
                st.subheader("⚛ Quantum Readiness Analytics")
                st.caption(
                    "Assessment of post-quantum security readiness across simulation runs."
                )

                c1, c2, c3 = st.columns(3)

                with c1:
                    st.metric(
                        "Average Score",
                        f"{qr_df['quantum_readiness_score'].mean():.1f}/100"
                    )

                with c2:
                    st.metric(
                        "Peak Score",
                        int(qr_df["quantum_readiness_score"].max())
                    )

                with c3:
                    st.metric(
                        "Minimum Score",
                        int(qr_df["quantum_readiness_score"].min())
                    )

        col1, col2 = st.columns([1,1], gap="small")
        with col1:
            st.markdown("#### Quantum Readiness Distribution")

            level_counts = (
                qr_df["quantum_readiness_level"]
                .value_counts()
                .reset_index()
            )

            level_counts.columns = [
                "Readiness",
                "Count"
            ]

            fig = px.pie(
                level_counts,
                names="Readiness",
                values="Count",
                hole=0.60,
                color="Readiness",
            )

            fig.update_traces(
                textposition="inside",
                textinfo="percent+label"
            )

            fig.update_layout(
                height=320,
                margin=dict(
                    l=20,
                    r=20,
                    t=40,
                    b=20,
                ),
                legend=dict(
                    orientation="v",
                    y=0.5,
                    yanchor="middle",
                    x=1.02,
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                key="quantum_readiness_distribution"
            )


        with col2:        
            st.caption("Average Component Scores")

            component_df = pd.DataFrame(
                qr_df["component_scores"].tolist()
            )

            avg_components = (
                component_df.mean()
                .reset_index()
            )

            avg_components.columns = [
                "Component",
                "Average Score"
            ]

            fig = px.line_polar(
                avg_components,
                r="Average Score",
                theta="Component",
                line_close=True,
            )

            fig.update_traces(
                fill="toself",
                line=dict(width=4),
            )

            fig.update_layout(
                height=320,
                showlegend=False,

                font=dict(
                    size=14
                ),

                margin=dict(
                    l=20,
                    r=20,
                    t=40,
                    b=20,
                ),

                polar=dict(
                    bgcolor="rgba(0,0,0,0)",

                    angularaxis=dict(
                        tickfont=dict(
                            size=13
                        )
                    ),

                    radialaxis=dict(
                        visible=True,
                        tickfont=dict(
                            size=12
                        ),
                        range=[
                            0,
                            max(
                                30,
                                avg_components["Average Score"].max() + 2
                            ),
                        ],
                    ),
                ),
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                key="quantum_component_scores"
            )
            st.info(
                "Component Weights • Cryptography: 30 | Security: 20 | Resources: 15 | Network: 10 | Energy: 10 | Execution: 10 | Context: 5"
            )



        st.markdown("#### Quantum Readiness Trend")

        trend_df = qr_df.copy()

        trend_df["rolling_avg"] = (
            trend_df["quantum_readiness_score"]
            .rolling(
                window=20,
                min_periods=1
            )
            .mean()
        )

        trend_df = trend_df.set_index("run_id")

        st.line_chart(
            trend_df[
                [
                    "quantum_readiness_score",
                    "rolling_avg"
                ]
            ]
        )
        a,b = st.columns([1,1], gap="small")
        with a:
            st.caption("Local vs Edge")

            execution_counts = (
                df["execution"]
                .value_counts()
                .reset_index()
            )

            execution_counts.columns = [
                "Execution",
                "Count"
            ]

            fig = px.pie(
                execution_counts,
                names="Execution",
                values="Count",
                hole=0.60,
                color="Execution",
            )

            fig.update_traces(
                textposition="inside",
                textinfo="percent+label"
            )

            fig.update_layout(
                height=320,
                margin=dict(
                    l=20,
                    r=20,
                    t=40,
                    b=20,
                ),
                legend=dict(
                    orientation="v",
                    y=0.5,
                    yanchor="middle",
                    x=1.02,
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                key="execution_distribution"
            )
        with b:
            st.caption("KEM Usage")
            fig.update_layout(
                height=300,
                showlegend=False,
                margin=dict(
                    l=20,
                    r=20,
                    t=40,
                    b=20,
                )
            )
            st.bar_chart(df["kem_used"].value_counts())
        c,d = st.columns([1,1], gap="small")
        with c:
            if "security_strategy" in df.columns:
                st.caption("Security Strategy Distribution")
                fig.update_layout(
                    height=320,
                    showlegend=False,
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    )
                )
                st.bar_chart(
                    df["security_strategy"].value_counts()
                )
        with d:
            if "signature_used" in df.columns:
                st.caption("Signature Usage")
                fig.update_layout(
                    height=320,
                    showlegend=False,
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    )
                )
                st.bar_chart(
                    df["signature_used"].value_counts()
                )
        st.caption("Avg Execution Time")
        st.bar_chart(df.groupby("execution")["execution_time_ms"].mean())
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


        with st.container(border=True):

            st.markdown("## ⚡ Energy Analytics")

            st.caption(
                "Energy consumption trends and resource-aware security analysis."
            )
            if "estimated_energy" in df.columns:

                energy_df = df.dropna(subset=["estimated_energy"])

                if not energy_df.empty:
                
                    c1, c2, c3 = st.columns(3)

                    with c1:
                        st.metric(
                            "Average Energy",
                            f"{energy_df['estimated_energy'].mean():.2f}"
                        )

                    with c2:
                        st.metric(
                            "Peak Energy",
                            f"{energy_df['estimated_energy'].max():.2f}"
                        )

                    with c3:
                        st.metric(
                            "Minimum Energy",
                            f"{energy_df['estimated_energy'].min():.2f}"
                        )
            st.markdown("#### Estimated Energy Trend")

            if (
                "estimated_energy" in df.columns
            ):

                energy_df = df.dropna(
                    subset=["estimated_energy"]
                ).copy()

                if not energy_df.empty:
                
                    energy_df["rolling_avg"] = (
                        energy_df["estimated_energy"]
                        .rolling(
                            window=20,
                            min_periods=1
                        )
                        .mean()
                    )

                    energy_df = energy_df.set_index(
                        "run_id"
                    )

                    st.line_chart(
                        energy_df[
                            [
                                "estimated_energy",
                                "rolling_avg"
                            ]
                        ]
                    )
            col1, col2 = st.columns([1,1], gap="small")

            with col1:
            
                st.markdown("#### Threat Level vs Estimated Energy")

                if (
                    "threat_level" in df.columns
                    and "estimated_energy" in df.columns
                ):

                    threat_energy = (
                        df.groupby("threat_level")["estimated_energy"]
                        .mean()
                        .reindex(
                            ["SAFE", "LOW", "MEDIUM", "HIGH"]
                        )
                        .reset_index()
                    )

                    fig = px.bar(
                        threat_energy,
                        x="threat_level",
                        y="estimated_energy",
                        color="threat_level",
                    )

                    fig.update_layout(
                        height=300,
                        showlegend=False,
                        margin=dict(
                            l=20,
                            r=20,
                            t=40,
                            b=20,
                        )
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        key="threat_energy_chart"
                    )

            with col2:
            
                st.markdown("#### Application Context vs Estimated Energy")

                if (
                    "context_profile" in df.columns
                    and "estimated_energy" in df.columns
                ):

                    context_energy = (
                        df.groupby("context_profile")["estimated_energy"]
                        .mean()
                        .reset_index()
                    )

                    fig = px.bar(
                        context_energy,
                        x="context_profile",
                        y="estimated_energy",
                        color="context_profile",
                    )

                    fig.update_layout(
                        height=300,
                        showlegend=False,
                        margin=dict(
                            l=20,
                            r=20,
                            t=40,
                            b=20,
                        )
                    )

                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        key="context_energy_chart"
                    )
            st.markdown("#### Security Strategy vs Estimated Energy")

            if (
                "security_strategy" in df.columns
                and "estimated_energy" in df.columns
            ):

                strategy_energy = (
                    df.groupby("security_strategy")["estimated_energy"]
                    .mean()
                    .reset_index()
                )

                fig = px.bar(
                    strategy_energy,
                    x="security_strategy",
                    y="estimated_energy",
                    color="security_strategy",
                    # title="Average Estimated Energy by Security Strategy"
                )
                fig.update_layout(
                    height=300,
                    showlegend=False,
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    )
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    key="strategy_energy_chart"
                )
            st.markdown("#### Resource Trends")

            cpu_tab, mem_tab, batt_tab = st.tabs(
                [
                    "🖥 CPU",
                    "💾 Memory",
                    "🔋 Battery"
                ]
            )

            with cpu_tab:
                if "cpu" in df.columns:
                    cpu_df = df.dropna(subset=["cpu"])
                    if not cpu_df.empty:
                        cpu_df = cpu_df.set_index("run_id")
                        st.line_chart(cpu_df["cpu"])

            with mem_tab:
                if "memory" in df.columns:
                    mem_df = df.dropna(subset=["memory"])
                    if not mem_df.empty:
                        mem_df = mem_df.set_index("run_id")
                        st.line_chart(mem_df["memory"])

            with batt_tab:
                if "battery" in df.columns:
                    batt_df = df.dropna(subset=["battery"])
                    if not batt_df.empty:
                        batt_df = batt_df.set_index("run_id")
                        st.line_chart(batt_df["battery"])


        st.subheader("🛡 Threat Analytics")
        st.caption(
            "Threat evolution, override behavior and adaptive security decisions."
        )
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
        left, right = st.columns([4,1])
        if "threat_score" in threat_df.columns:
            left, right = st.columns([3.5,1])
            with left:
                st.markdown("#### Threat Score Trend")
                score_df = threat_df.dropna(
                    subset=["threat_score"]
                )
                if not score_df.empty:
                    score_df = score_df.sort_values("run_id")   
                    fig = go.Figure()   
                    fig.add_trace(
                        go.Scatter(
                            x=score_df["run_id"],
                            y=score_df["threat_score"],
                            mode="lines",
                            name="Threat Score",
                            line=dict(width=3)
                        )
                    )
                    fig.add_hline(
                    y=100,
                    line_dash="dash",
                    line_color="red",
                    annotation_text="HIGH",
                    annotation_position="right",
                    annotation_font_color="red"
                    )
                    fig.add_hline(
                    y=75,
                    line_dash="dash",
                    line_color="orange",
                    annotation_text="MEDIUM",
                    annotation_position="right",
                    annotation_font_color="orange"
                    )
                    fig.add_hline(
                    y=50,
                    line_dash="dash",
                    line_color="gold",
                    annotation_text="LOW",
                    annotation_position="right",
                    annotation_font_color="gold"
                    )
                    fig.add_hline(
                    y=25,
                    line_dash="dash",
                    line_color="limegreen",
                    annotation_text="SAFE",
                    annotation_position="right",
                    annotation_font_color="limegreen"
                    )
                    legend=dict(
                        orientation="v",
                        y=1,
                        x=1.02
                    )
                    fig.update_layout(
                    xaxis_title="Run ID",
                    yaxis_title="Threat Score",
                    height=320,
                    legend=dict(
                        orientation="v",
                        y=1,
                        x=1.02,
                        yanchor="top"
                    ),
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    )
                    )
                    st.plotly_chart(
                        fig,
                        use_container_width=True,
                        key="threat_score_trend"
                    )
            with right:
                st.caption("Threat Summary")
                summary = (
                    threat_df["threat_level"]
                    .value_counts()
                    .reindex(
                        ["HIGH", "MEDIUM", "LOW", "SAFE"],
                        fill_value=0
                    )
                )
                st.metric("🔴 HIGH (≥75)", summary["HIGH"])
                st.metric("🟠 MEDIUM (50-74)", summary["MEDIUM"])
                st.metric("🟡 LOW (26-49)", summary["LOW"])
                st.metric("🟢 SAFE (<25)", summary["SAFE"])
                st.metric("📊 Total Runs", len(threat_df))
        col1, col2 = st.columns([1, 1], gap="small")
        with col1:
            if "threat_override" in threat_df.columns:
                st.markdown("#### Threat Override Statistics")
                override_counts = (
                    threat_df["threat_override"]
                    .map({
                        True: "Override Active",
                        False: "Normal Decision"
                    })
                    .value_counts()
                    .reset_index()
                )

                override_counts.columns = [
                    "Threat Override",
                    "Count"
                ]
                fig = px.pie(
                    override_counts,
                    names="Threat Override",
                    values="Count",
                    color="Threat Override",
                    color_discrete_map={
                        "Override Active": "#ef4444",
                        "Normal Decision": "#6b7280"
                    }
                )

                fig.update_traces(
                    textposition="inside",
                    textinfo="percent+label"
                )

                fig.update_layout(
                    height=320,
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    ),
                    legend=dict(
                        orientation="v",
                        y=0.5,
                        yanchor="middle",
                        x=1.02,
                    )
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    key="override_statistics"
                )
        with col2:
            if (
                "threat_level" in threat_df.columns
                and
                "mode" in threat_df.columns
            ):
                st.markdown("#### Threat Level vs Security Mode")
                threat_mode = pd.crosstab(
                    threat_df["threat_level"],
                    threat_df["mode"]
                )
                fig = px.bar(
                    threat_mode,
                    barmode="stack",
                    color_discrete_sequence=[
                        "#22c55e",   # Performance
                        "#f59e0b",   # Balanced
                        "#ef4444"    # High Security
                    ]
                )
                fig.update_layout(
                    height=300,
                    showlegend=False,
                    margin=dict(
                        l=20,
                        r=20,
                        t=40,
                        b=20,
                    )
                )
                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    key="threat_mode_chart"
                )
        if (
            "threat_level" in threat_df.columns
            and
            "kem_used" in threat_df.columns
        ):  
            st.markdown("#### Threat Level vs KEM Selection")
            threat_kem = pd.crosstab(
                threat_df["threat_level"],
                threat_df["kem_used"]
            )
            fig = px.bar(
                threat_kem,
                barmode="stack",
                color_discrete_sequence=[
                    "#93c5fd",   # ML-KEM-512
                    "#3b82f6",   # ML-KEM-768
                    "#1d4ed8",   # ML-KEM-1024
                    "#8b5cf6"    # FrodoKEM
                ]
            )
            fig.update_layout(
                height=300,
                showlegend=True,
                margin=dict(
                    l=20,
                    r=20,
                    t=40,
                    b=20,
                )
            )
            st.plotly_chart(
                fig,
                use_container_width=True,
                key="threat_kem_chart"
            )
    else:
        st.info("No result logs yet.")