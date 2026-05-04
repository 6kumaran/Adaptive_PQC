from fastapi import FastAPI
from pydantic import BaseModel
import time
import oqs

app = FastAPI()


# -----------------------------
# Request Format
# -----------------------------
class OffloadRequest(BaseModel):
    kem: str
    signature: str
    mode: str


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

    kem_result = run_kem_algorithm(request.kem)

    end = time.time()

    return {
        "status": "success",
        "kem_used": request.kem,
        "signature_used": request.signature,
        "mode": request.mode,
        "kem_success": kem_result,
        "execution_time_ms": round((end - start) * 1000, 2)
    }