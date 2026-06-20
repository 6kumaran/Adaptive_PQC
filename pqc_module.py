import oqs
import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Dynamic KEM ----------
def kem_keygen(kem_name):
    kem = oqs.KeyEncapsulation(kem_name)
    public_key = kem.generate_keypair()
    return kem, public_key

def kem_encrypt(kem, public_key):
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def kem_decrypt(kem, ciphertext):
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# ---------- SIGNATURE (Dilithium) ----------
def dilithium_keygen():
    sig = oqs.Signature("Dilithium2")
    public_key = sig.generate_keypair()
    return sig, public_key

def dilithium_sign(sig, message):
    return sig.sign(message)

def dilithium_verify(sig, message, signature, public_key):
    return sig.verify(message, signature, public_key)


# ---------- TEST ----------
if __name__ == "__main__":
    # Kyber test
    kem, pk = kyber_keygen()
    ct, ss1 = kyber_encrypt(kem, pk)
    ss2 = kyber_decrypt(kem, ct)
    print("Kyber working:", ss1 == ss2)

    # Dilithium test
    sig, pk_s = dilithium_keygen()
    msg = b"Hello PQC"
    signature = dilithium_sign(sig, msg)
    print("Dilithium verify:", dilithium_verify(sig, msg, signature, pk_s))

# ---------- KEM (Kyber / ML-KEM) ----------
def kyber_keygen():
    kem = oqs.KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()
    return kem, public_key

def kyber_encrypt(kem, public_key):
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def kyber_decrypt(kem, ciphertext):
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# ---------- SIGNATURE (Dilithium) ----------
def dilithium_keygen():
    sig = oqs.Signature("Dilithium2")
    public_key = sig.generate_keypair()
    return sig, public_key

def dilithium_sign(sig, message):
    signature = sig.sign(message)
    return signature

def dilithium_verify(sig, message, signature, public_key):
    return sig.verify(message, signature, public_key)


# ----------------------------------------
# AES Key Derivation
# ----------------------------------------

def derive_aes_key(shared_secret):
    return hashlib.sha256(shared_secret).digest()


# ----------------------------------------
# AES-GCM Encryption
# ----------------------------------------

def encrypt_message(shared_secret, message):

    aes_key = derive_aes_key(shared_secret)

    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode(),
        None
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


# ----------------------------------------
# AES-GCM Decryption
# ----------------------------------------

def decrypt_message(shared_secret, nonce_b64, ciphertext_b64):

    aes_key = derive_aes_key(shared_secret)

    aesgcm = AESGCM(aes_key)

    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()

# ----------------------------------------
# Generic PQC Signatures
# ----------------------------------------

def signature_keygen(signature_name):

    signer = oqs.Signature(signature_name)

    public_key = signer.generate_keypair()

    return signer, public_key


def sign_payload(signature_name, message_bytes):

    signer = oqs.Signature(signature_name)

    public_key = signer.generate_keypair()

    signature = signer.sign(message_bytes)

    return {
        "signature": base64.b64encode(signature).decode(),
        "public_key": base64.b64encode(public_key).decode()
    }


def verify_payload(
        signature_name,
        message_bytes,
        signature_b64,
        public_key_b64):

    verifier = oqs.Signature(signature_name)

    signature = base64.b64decode(signature_b64)

    public_key = base64.b64decode(public_key_b64)

    return verifier.verify(
        message_bytes,
        signature,
        public_key
    )

# ---------- TEST EXECUTION ----------
if __name__ == "__main__":
    print("=== PQC MODULE TEST START ===")

    # --- Kyber Test ---
    kem, public_key = kyber_keygen()
    ciphertext, ss1 = kyber_encrypt(kem, public_key)
    ss2 = kyber_decrypt(kem, ciphertext)

    print("Kyber Key Exchange Successful:", ss1 == ss2)

    # --- Dilithium Test ---
    message = b"Hello PQC World"
    sig, pub_key_sig = dilithium_keygen()
    signature = dilithium_sign(sig, message)

    verification = dilithium_verify(sig, message, signature, pub_key_sig)
    print("Dilithium Signature Verified:", verification)

    print("=== PQC MODULE TEST END ===")