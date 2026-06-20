import requests
import json
import os
import time
from datetime import datetime
import base64
from pqc_module import sign_payload

from pqc_module import (
    kem_keygen,
    kem_encrypt,
    kem_decrypt,
    encrypt_message
)
from iot_device import IoTDevice
from decision_engine import decide_execution
from pqc_module import kem_keygen, kem_encrypt, kem_decrypt

# -----------------------------
# Edge Server URL
# -----------------------------
EDGE_SERVER_URL = "http://127.0.0.1:8000/offload"

# -----------------------------
# Results Folder
# -----------------------------
RESULTS_FOLDER = "results"
os.makedirs(RESULTS_FOLDER, exist_ok=True)


# -----------------------------
# Send Task to Edge Server
# -----------------------------
def send_offload_request(
        kem,
        encrypted_payload,
        shared_secret,
        signature_data,
        signature_algorithm):

    payload = {
        "kem": kem,
        "ciphertext": encrypted_payload["ciphertext"],
        "nonce": encrypted_payload["nonce"],
        "shared_secret": base64.b64encode(
            shared_secret
        ).decode(),

        "signature_algorithm": signature_algorithm,
        "signature": signature_data["signature"],
        "public_key": signature_data["public_key"]
    }

    try:

        response = requests.post(
            EDGE_SERVER_URL,
            json=payload
        )

        return response.json()

    except Exception as e:

        return {
            "status": "failed",
            "error": str(e)
        }

# -----------------------------
# Save Result
# -----------------------------
def save_result(data):
    filename = datetime.now().strftime("%Y%m%d_%H%M%S.json")
    filepath = os.path.join(RESULTS_FOLDER, filename)

    with open(filepath, "w") as file:
        json.dump(data, file, indent=4)


# -----------------------------
# Main Flow
# -----------------------------
def main():
    print("\n--- Adaptive PQC Offloading Client ---")

    # Get live device status
    device = IoTDevice()
    status = device.get_device_status()

    # Use your existing decision engine
    decision = decide_execution(status)

    kem = decision["kem"]
    signature = decision["signature"]
    mode = decision["execution"]   # local / edge

    print("Device Status:", status)
    print("Decision:", decision)

    # Only offload if edge selected
    if mode == "edge":

        user_message = input(
            "\nEnter Message To Send Securely: "
        )

        kem_obj, public_key = kem_keygen(kem)

        ciphertext, shared_secret = kem_encrypt(
            kem_obj,
            public_key
        )

        encrypted_payload = encrypt_message(
            shared_secret,
            user_message
        )

        signature_data = sign_payload(
            signature,
            encrypted_payload["ciphertext"].encode()
        )
       

        result = send_offload_request(
            kem,
            encrypted_payload,
            shared_secret,
            signature_data,
            signature
        )

        print("\n=== SECURE CHANNEL ===")

        print("\nOriginal Message:")
        print(user_message)

        print("\nEncrypted Payload:")
        print(
        encrypted_payload["ciphertext"][:80]
        + "..."
        )

        print("\nServer Response:")
        print(
            json.dumps(
                result,
                indent=4
            )
        )

        save_result(result)
        print("\nResult saved in results/ folder")

    else:
        print("\n--- Local Execution Started ---")

        start = time.time()

        kem_obj, public_key = kem_keygen(kem)
        ciphertext, ss1 = kem_encrypt(kem_obj, public_key)
        ss2 = kem_decrypt(kem_obj, ciphertext)

        end = time.time()

        result = {
            "status": "success",
            "kem_used": decision["kem"],
            "signature_used": signature,
            "mode": "local",
            "kem_success": ss1 == ss2,
            "execution_time_ms": round((end - start) * 1000, 2)
        }

        print(json.dumps(result, indent=4))

        save_result(result)
        print("\nResult saved in results/ folder")


if __name__ == "__main__":
    main()