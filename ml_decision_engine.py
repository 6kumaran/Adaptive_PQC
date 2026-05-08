import joblib
import pandas as pd

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


def ml_decide_execution(device_status):

    battery = device_status["battery"]
    cpu = device_status["cpu"]
    memory = device_status["memory"]
    network = network_map[device_status["network"]]

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

    if mode == "performance":
        signature = "Dilithium2"
    elif mode == "balanced":
        signature = "Falcon512"
    else:
        signature = "SPHINCS+"

    return {
        "execution": execution,
        "mode": mode,
        "kem": kem,
        "signature": signature
    }