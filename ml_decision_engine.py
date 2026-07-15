import joblib
import pandas as pd
from decision_engine import assess_threat
from adaptive_security_policy import apply_security_policy
from energy_model import estimate_energy
from latency_model import estimate_latency
from pqc_module import resolve_signature_name

# Load models
model_exec = joblib.load("model_execution.pkl")
model_mode = joblib.load("model_mode.pkl")

network_map = {
    "good": 2,
    "moderate": 1,
    "poor": 0
}

reverse_exec = {1: "local", 0: "edge"}
reverse_mode = {
    0: "performance",
    1: "balanced",
    2: "high_security"
}


def ml_decide_execution(
    device_status,
    threat_profile="AUTO",
    threat_data=None,
    context_profile="BALANCED"
):

    battery = device_status["battery"]
    cpu = device_status["cpu"]
    memory = device_status["memory"]
    network = network_map[device_status["network"]]
    # --------------------------------
    # Threat Assessment
    # --------------------------------
    if threat_data is None:
        threat_data = assess_threat(threat_profile)
    threat_override = False

    X = pd.DataFrame([{
    "battery": battery,
    "cpu": cpu,
    "memory": memory,
    "network": network
    }])

    exec_pred = model_exec.predict(X)[0]
    mode_pred = model_mode.predict(X)[0]

    execution = reverse_exec[exec_pred]
    mode = reverse_mode[mode_pred]

    policy = apply_security_policy(
    battery=battery,
    cpu=cpu,
    memory=memory,
    security_mode=mode,
    threat_data=threat_data,
    context_profile=context_profile
    )
    energy = estimate_energy(
    cpu_usage=cpu,
    memory_usage=memory,
    network_quality=device_status["network"],
    security_strategy=policy["security_strategy"],
    kem_algorithm=policy["kem"],
    signature_algorithm=policy["signature"],
    execution_location=execution,
    )
    latency = estimate_latency(
        cpu_usage=cpu,
        memory_usage=memory,
        network_quality=device_status["network"],
        execution_location=execution,
    )
    # --------------------------------
    # Latency-Aware Optimization
    # --------------------------------

    security_strategy = policy["security_strategy"]
    kem = policy["kem"]
    signature = resolve_signature_name(policy["signature"])

    latency_optimization = False
    latency_reason = "Latency optimization not applied"

    latency_category = latency["latency_category"]
    threat_level = threat_data["threat_level"]

    if (
        context_profile != "MISSION_CRITICAL"
    ):

        if (
            latency_category in ["HIGH", "CRITICAL"]
            and threat_level in ["SAFE", "LOW"]
        ):

            latency_optimization = True

            latency_reason = (
                "High latency with low threat - "
                "optimized for performance"
            )

            if security_strategy == "HYBRID":

                security_strategy = "PQC"
                kem = "ML-KEM-768"
                signature = resolve_signature_name("Dilithium3")

            elif security_strategy == "PQC":

                security_strategy = "CLASSICAL"
                kem = "ML-KEM-512"
                signature = resolve_signature_name("Dilithium2")

    elif context_profile == "MISSION_CRITICAL":

        latency_reason = (
            "Mission Critical profile - "
            "security prioritized over latency"
        )

    return {
    "execution": execution,
    "mode": policy["security_mode"],
    "security_strategy": security_strategy,
    "kem": kem,
    "signature": signature,
    "threat_override": policy["threat_override"],

    "context_profile": policy["context_profile"],
    "context_priority": policy["context_priority"],
    "context_description": policy["context_description"],

    "threat_profile": threat_data["threat_profile"],
    "threat_score": threat_data["threat_score"],
    "threat_level": threat_data["threat_level"],
    "threat_indicators": threat_data["indicators"],
    "latency_optimization":
        latency_optimization,

    "latency_reason":
        latency_reason,

    **energy,
    **latency
    }