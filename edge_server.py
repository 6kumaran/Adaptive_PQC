from typing import Set
from fastapi import FastAPI
from pydantic import BaseModel
import time

from requests import request
import oqs
import base64

from pqc_module import (
    decrypt_message,
    resolve_kem_name,
    verify_payload,
    classical_verify
)

app = FastAPI()

# -----------------------------
# Replay Protection Settings
# -----------------------------
MESSAGE_EXPIRY_SECONDS = 60

# -----------------------------
# Replay Protection Cache
# -----------------------------
seen_message_ids: Set[str] = set()

# -----------------------------
# Request Format
# -----------------------------
class OffloadRequest(BaseModel):
    kem: str
    message_id: str
    timestamp: float
    ciphertext: str
    nonce: str
    shared_secret: str

    signature_algorithm: str
    signature: str
    public_key: str
    classical_signature_algorithm: str | None = None

    classical_signature: str | None = None

    classical_public_key: str | None = None


# -----------------------------
# Edge PQC Task
# -----------------------------
def run_kem_algorithm(kem_name):
    kem = oqs.KeyEncapsulation(resolve_kem_name(kem_name))

    public_key = kem.generate_keypair()
    ciphertext, secret1 = kem.encap_secret(public_key)
    secret2 = kem.decap_secret(ciphertext)

    return secret1 == secret2


# -----------------------------
# API Route
# -----------------------------
@app.post("/offload")
def offload_task(request: OffloadRequest):
    start = time.time()

    try:

        shared_secret = base64.b64decode(
            request.shared_secret
        )
        # -----------------------------
        # Replay Attack Detection
        # -----------------------------
        if request.message_id in seen_message_ids:

            return {
                "status": "rejected",
                "replay_detected": True,
                "message": "Replay Attack Detected"
            }

        # -----------------------------
        # Timestamp Validation
        # -----------------------------
        current_time = time.time()

        if current_time - request.timestamp > MESSAGE_EXPIRY_SECONDS:

            return {
                "status": "rejected",
                "expired": True,
                "message": "Message Expired"
            }
        
        # Only cache valid messages
        seen_message_ids.add(request.message_id)

        print("Received Algorithm:", request.signature_algorithm)
        print("Ciphertext:", request.ciphertext[:60])
        print("Signature Length:", len(request.signature))
        print("Public Key Length:", len(request.public_key))
        verified = verify_payload(
            request.signature_algorithm,
            request.ciphertext.encode(),
            request.signature,
            request.public_key
        )

        if not verified:

            return {
                "status": "rejected",
                "signature_verified": False,
                "message": "Tampered Payload"
            }
        # ------------------------------------
        # Classical Verification (Hybrid)
        # ------------------------------------

        if request.classical_signature:

            classical_verified = classical_verify(
                request.classical_public_key,
                request.classical_signature,
                request.ciphertext.encode()
            )

            if not classical_verified:

                return {
                    "status": "rejected",

                    "signature_verified": False,

                    "classical_signature_verified": False,

                    "message": "Classical Signature Verification Failed"
                }

        decrypted_message = decrypt_message(
            shared_secret,
            request.nonce,
            request.ciphertext
        )
        
        end = time.time()

        return {
            "status": "success",
            "signature_algorithm":
                request.signature_algorithm,

            "signature_verified": True,

            "classical_signature_verified":
                True if request.classical_signature
                else None,

            "decrypted_message":
                decrypted_message,

            "execution_time_ms":
                round((end-start)*1000,2)
        }

    except Exception as e:

        return {
            "status": "failed",
            "error": str(e)
        }