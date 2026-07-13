import requests
import base64
import time, os
import uuid
import copy
from pqc_module import (
    kem_keygen,
    kem_encrypt,
    encrypt_message,
    sign_payload,
    classical_keygen,
    classical_sign
)

EDGE_SERVER_URL = os.getenv(
    "EDGE_SERVER_URL",
    "http://127.0.0.1:8000/offload"
)

# ----------------------------------
# Security Test Modes
# ----------------------------------

class SecurityTestMode:
    
    NORMAL = "Normal"

    REPLAY = "Replay Previous Packet"

    EXPIRED = "Expired Packet"

    TAMPERED = "Tampered Signature"


# Stores the most recently transmitted packet
last_packet = None


def send_secure_message(message, decision,
        test_mode=SecurityTestMode.NORMAL):
    print("Strategy:", decision["security_strategy"])
    start = time.time()
    payload, metadata = _build_secure_packet(
        message,
        decision
    )
    payload = _apply_test_mode(
        payload,
        test_mode
    )

    result = _send_packet(
        payload
    )

    end = time.time()

    print(">>> USING UPDATED SECURE_CHANNEL.PY <<<")

    return {
    "status": "success",
    "record_type": "secure_channel",

    "security_strategy":
        decision["security_strategy"],

    "kem": metadata["kem"],
    "signature": metadata["signature"],

    "ciphertext": metadata["ciphertext"],

    "ciphertext_size":
        metadata["ciphertext_size"],

    "signature_size":
        metadata["signature_size"],

    "execution_time_ms":
        round((end-start)*1000, 2),

    "response": result
    }
def _build_secure_packet(message, decision):

    kem = decision["kem"]
    signature = decision["signature"]
    security_strategy = decision["security_strategy"]

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
    classical_signature_data = None

    if security_strategy == "HYBRID":

        private_key, public_key = classical_keygen()

        classical_signature_data = classical_sign(
            private_key,
            encrypted_payload["ciphertext"].encode()
        )

    message_id = str(uuid.uuid4())
    timestamp = time.time()

    payload = {
        "kem": kem,
        "message_id": message_id,
        "timestamp": timestamp,

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
    if classical_signature_data:

        payload["classical_signature_algorithm"] = "ECDSA-P256"

        payload["classical_signature"] = (
            classical_signature_data["signature"]
        )

        payload["classical_public_key"] = (
            classical_signature_data["public_key"]
        )

    metadata = {
        "kem": kem,
        "signature": signature,
        "ciphertext": encrypted_payload["ciphertext"],
        "ciphertext_size": len(encrypted_payload["ciphertext"]),
        "signature_size": len(signature_data["signature"])
    }
    if classical_signature_data:

        metadata["classical_signature_algorithm"] = "ECDSA-P256"

        metadata["classical_signature_size"] = len(
            classical_signature_data["signature"]
        )

    return payload, metadata

def _apply_test_mode(payload, mode):

    global last_packet

    if mode == SecurityTestMode.NORMAL:

        last_packet = copy.deepcopy(payload)
        return payload

    elif mode == SecurityTestMode.REPLAY:

        if last_packet is not None:
            return last_packet

        return payload

    elif mode == SecurityTestMode.EXPIRED:

        payload["timestamp"] -= 120

        return payload

    elif mode == SecurityTestMode.TAMPERED:

        sig = payload["signature"]

        payload["signature"] = (
            "A" if sig[0] != "A" else "B"
        ) + sig[1:]

        return payload

    return payload

def _send_packet(payload):

    try:
        response = requests.post(
            EDGE_SERVER_URL,
            json=payload,
            timeout=10
        )

        result = response.json()

        return result

    except Exception as e:

        return {
            "status": "failed",
            "error": str(e)
        }