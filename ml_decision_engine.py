import joblib
import pandas as pd
from decision_engine import assess_threat


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
    threat_data=None
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
    # ------------------------------
    # Threat-Aware Security Override
    # ------------------------------

    threat_level = threat_data["threat_level"]

    original_mode = mode

    if threat_level == "LOW":

        if mode == "performance":
            mode = "balanced"

    elif threat_level == "MEDIUM":

        mode = "high_security"

    elif threat_level == "HIGH":

        mode = "high_security"

    if original_mode != mode:
        threat_override = True

    # ------------------------------
    # SAME LOGIC AS YOUR ORIGINAL
    # ------------------------------

    if mode == "performance":
        kem = "ML-KEM-512"
    elif mode == "balanced":
        kem = "ML-KEM-768"
    else:
        kem = "ML-KEM-1024"

    if memory > 70 and cpu < 60:
        kem = "FrodoKEM-640-AES"

    if threat_level == "HIGH":

        kem = "ML-KEM-1024"

        threat_override = True

    if mode == "performance":
        signature = "Dilithium2"
    elif mode == "balanced":
        signature = "Dilithium3"
    else:
        signature = "SPHINCS+-SHAKE-128f-simple"

    if threat_level == "HIGH":
        signature = "SPHINCS+-SHAKE-128f-simple"
    # ------------------------------
    # Security Strategy
    # ------------------------------

    if threat_level == "SAFE":
        security_strategy = "CLASSICAL"

    elif threat_level in ["LOW", "MEDIUM"]:
        security_strategy = "PQC"

    else:
        security_strategy = "HYBRID"

    print(threat_data)

    return {
    "execution": execution,
    "mode": mode,

    "security_strategy": security_strategy,

    "kem": kem,
    "signature": signature,

    "threat_profile":
        threat_data["threat_profile"],

    "threat_score":
        threat_data["threat_score"],

    "threat_level":
        threat_data["threat_level"],

    "threat_override":
        threat_override,

    "threat_indicators":
        threat_data["indicators"]
}