from fastapi import FastAPI
from pydantic import BaseModel
import time
import oqs
import base64

from pqc_module import (
    decrypt_message,
    verify_payload
)

app = FastAPI()


# -----------------------------
# Request Format
# -----------------------------
class OffloadRequest(BaseModel):
    kem: str
    ciphertext: str
    nonce: str
    shared_secret: str

    signature_algorithm: str
    signature: str
    public_key: str


# -----------------------------
# Edge PQC Task
# -----------------------------
def run_kem_algorithm(kem_name):
    kem = oqs.KeyEncapsulation(kem_name)

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