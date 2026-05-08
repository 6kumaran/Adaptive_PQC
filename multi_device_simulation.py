from iot_device import IoTDevice
from decision_engine import decide_execution
from ml_decision_engine import ml_decide_execution
from pqc_module import kyber_keygen, kyber_encrypt, kyber_decrypt
import requests
import time

EDGE_SERVER_URL = "http://127.0.0.1:8000/offload"

# -----------------------------------
# Single Device Execution
# -----------------------------------
def execute_device(device_id, use_ml=False):

    device = IoTDevice()
    status = device.get_device_status()

    if use_ml:
        decision = ml_decide_execution(status)
    else:
        decision = decide_execution(status)

    mode = decision["execution"]
    kem = decision["kem"]
    signature = decision["signature"]

    start = time.time()

    if mode == "edge":
        try:
            payload = {
                "kem": kem,
                "signature": signature,
                "mode": mode
            }
            requests.post(EDGE_SERVER_URL, json=payload, timeout=5)
        except:
            pass
    else:
        kem_obj, pk = kyber_keygen()
        ct, ss1 = kyber_encrypt(kem_obj, pk)
        ss2 = kyber_decrypt(kem_obj, ct)

    end = time.time()

    return {
        "device_id": device_id,
        "mode": mode,
        "kem_used": kem,
        "signature_used": signature,
        "execution_time_ms": round((end-start)*1000,2)
    }

# -----------------------------------
# Multi Device Simulation
# -----------------------------------
def simulate_devices(n_devices=10, use_ml=False):

    results = []

    for i in range(n_devices):
        result = execute_device(i, use_ml)
        results.append(result)

    return results


# ---------- TEST ----------
if __name__ == "__main__":

    results = simulate_devices(10, use_ml=False)

    for r in results:
        print(r)