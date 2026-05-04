from iot_device import IoTDevice
import time


def decide_execution(device_status):

    battery = device_status["battery"]
    cpu = device_status["cpu"]
    memory = device_status["memory"]
    network = device_status["network"]

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

    # ------------------------------
    # Signature Selection
    # ------------------------------
    if mode == "performance":
        signature = "Dilithium2"
    elif mode == "balanced":
        signature = "Falcon512"
    else:
        signature = "SPHINCS+"

    return {
        "score": score,
        "execution": execution,
        "mode": mode,
        "kem": kem,
        "signature": signature
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