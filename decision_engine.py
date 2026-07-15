from iot_device import IoTDevice
import time
import random
from adaptive_security_policy import apply_security_policy
from energy_model import estimate_energy
from latency_model import estimate_latency
from pqc_module import resolve_signature_name
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

def decide_execution(device_status,threat_profile="AUTO",threat_data=None,context_profile="BALANCED"):
    

    battery = device_status["battery"]
    cpu = device_status["cpu"]
    memory = device_status["memory"]
    network = device_status["network"]
    if threat_data is None:
        threat_data = assess_threat(threat_profile)

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