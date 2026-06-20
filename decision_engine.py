from iot_device import IoTDevice
import time
import random

def assess_threat(threat_profile="AUTO"):

    import random

    if threat_profile == "AUTO":
        threat_profile = random.choice(
            ["SAFE", "LOW", "MEDIUM", "HIGH"]
        )

    indicators = []

    if threat_profile == "SAFE":

        threat_score = random.randint(0, 25)

        if random.random() < 0.3:
            indicators.append(
                "Minor Network Fluctuation"
            )

    elif threat_profile == "LOW":

        threat_score = random.randint(26, 50)

        indicators.append(
            "Failed Authentication Attempts"
        )

        if random.random() < 0.5:
            indicators.append(
                "Network Anomaly"
            )

    elif threat_profile == "MEDIUM":

        threat_score = random.randint(51, 75)

        indicators.extend([
            "Multiple Failed Authentication Attempts",
            "Network Anomaly"
        ])

        if random.random() < 0.7:
            indicators.append(
                "Signature Verification Failure"
            )

    else:  # HIGH

        threat_score = random.randint(76, 100)

        indicators.extend([
            "Replay Attack Indicator",
            "Signature Verification Failure",
            "Suspicious Edge Node",
            "Multiple Failed Authentication Attempts"
        ])

    return {
        "threat_profile": threat_profile,
        "threat_score": threat_score,
        "threat_level": threat_profile,
        "indicators": indicators
    }

def decide_execution(device_status,threat_profile="AUTO"):

    battery = device_status["battery"]
    cpu = device_status["cpu"]
    memory = device_status["memory"]
    network = device_status["network"]
    threat_data = assess_threat(
    threat_profile
    )
    threat_override = False

    score = 0

    # Battery
    if battery > 70:
        score += 2
    elif battery > 40:
        score += 1

    # CPU (lower better)
    if cpu < 40:
        score += 2
    elif cpu < 75:
        score += 1

    # Memory (lower better)
    if memory < 50:
        score += 2
    elif memory < 75:
        score += 1

    # Network
    if network == "good":
        score += 2
    elif network == "moderate":
        score += 1

    # ------------------------------
    # Execution Decision
    # ------------------------------
    if score >= 6:
        execution = "local"
    else:
        execution = "edge"

    # ------------------------------
    # Security Mode
    # ------------------------------
    if score >= 7:
        mode = "high_security"
    elif score >= 5:
        mode = "balanced"
    else:
        mode = "performance"
    
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
    # KEM Selection
    # ------------------------------
    if mode == "performance":
        kem = "ML-KEM-512"
    elif mode == "balanced":
        kem = "ML-KEM-768"
    else:
        kem = "ML-KEM-1024"

    # Use Frodo if memory is high but CPU moderate
    if memory > 70 and cpu < 60:
        kem = "FrodoKEM-640-AES"
    
    if threat_level == "HIGH":

        kem = "ML-KEM-1024"
        signature = "SPHINCS+-SHAKE-128f-simple"

        threat_override = True

    # ------------------------------
    # Signature Selection
    # ------------------------------
    if mode == "performance":
        signature = "Dilithium2"
    elif mode == "balanced":
        signature = "Dilithium3"
    else:
        signature = "SPHINCS+-SHAKE-128f-simple"

    return {
    "score": score,
    "execution": execution,
    "mode": mode,
    "kem": kem,
    "signature": signature,

    "threat_override": threat_override,

    "threat_profile":
        threat_data["threat_profile"],

    "threat_score":
        threat_data["threat_score"],

    "threat_level":
        threat_data["threat_level"],

    "threat_indicators":
        threat_data["indicators"]
    }


# ---------- LIVE TEST ----------
if __name__ == "__main__":

    device = IoTDevice()

    print("=== DECISION ENGINE START ===")

    for _ in range(5):
        status = device.get_device_status()
        decision = decide_execution(status)

        print("Device:", status)
        print("Decision:", decision)
        print("-" * 40)

        time.sleep(2)

    print("=== END ===")