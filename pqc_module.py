import oqs
import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)
from cryptography.exceptions import InvalidSignature

# ----------------------------------------
# Signature compatibility layer
# ----------------------------------------

_ENABLED_SIGS = set(oqs.get_enabled_sig_mechanisms())

SIGNATURE_ALIASES = {

    # Dilithium -> ML-DSA
    "Dilithium2": "ML-DSA-44",
    "Dilithium3": "ML-DSA-65",
    "Dilithium5": "ML-DSA-87",

    # SPHINCS+ -> SLH-DSA (PURE variants)

    "SPHINCS+-SHAKE-128f-simple": "SLH_DSA_PURE_SHAKE_128F",
    "SPHINCS+-SHAKE-128s-simple": "SLH_DSA_PURE_SHAKE_128S",

    "SPHINCS+-SHAKE-192f-simple": "SLH_DSA_PURE_SHAKE_192F",
    "SPHINCS+-SHAKE-192s-simple": "SLH_DSA_PURE_SHAKE_192S",

    "SPHINCS+-SHAKE-256f-simple": "SLH_DSA_PURE_SHAKE_256F",
    "SPHINCS+-SHAKE-256s-simple": "SLH_DSA_PURE_SHAKE_256S",

    "SPHINCS+-SHA2-128f-simple": "SLH_DSA_PURE_SHA2_128F",
    "SPHINCS+-SHA2-128s-simple": "SLH_DSA_PURE_SHA2_128S",

    "SPHINCS+-SHA2-192f-simple": "SLH_DSA_PURE_SHA2_192F",
    "SPHINCS+-SHA2-192s-simple": "SLH_DSA_PURE_SHA2_192S",

    "SPHINCS+-SHA2-256f-simple": "SLH_DSA_PURE_SHA2_256F",
    "SPHINCS+-SHA2-256s-simple": "SLH_DSA_PURE_SHA2_256S",
}



def resolve_signature_name(name: str) -> str:
    """
    Automatically maps old liboqs names to the
    currently installed implementation.
    """

    if name in _ENABLED_SIGS:
        return name

    if name in SIGNATURE_ALIASES:
        alias = SIGNATURE_ALIASES[name]
        if alias in _ENABLED_SIGS:
            return alias

    raise ValueError(
        f"Signature algorithm '{name}' is unavailable.\n"
        f"Available algorithms:\n{sorted(_ENABLED_SIGS)}"
    )

_ENABLED_KEMS = set(oqs.get_enabled_kem_mechanisms())

KEM_ALIASES = {

    "Kyber512": "ML-KEM-512",
    "Kyber768": "ML-KEM-768",
    "Kyber1024": "ML-KEM-1024",

    "ML-KEM-512": "ML-KEM-512",
    "ML-KEM-768": "ML-KEM-768",
    "ML-KEM-1024": "ML-KEM-1024",
}


def resolve_kem_name(name: str):

    if name in _ENABLED_KEMS:
        return name

    if name in KEM_ALIASES:
        alias = KEM_ALIASES[name]
        if alias in _ENABLED_KEMS:
            return alias

    raise ValueError(
        f"KEM '{name}' unavailable.\nAvailable:\n{sorted(_ENABLED_KEMS)}"
    )

# ---------- Dynamic KEM ----------
def kem_keygen(kem_name):
    kem = oqs.KeyEncapsulation(resolve_kem_name(kem_name))
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
    sig = oqs.Signature(resolve_signature_name("Dilithium2"))
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
    kem = oqs.KeyEncapsulation(resolve_kem_name("Kyber768"))
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
    sig = oqs.Signature(resolve_signature_name("Dilithium2"))
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

    signer = oqs.Signature(resolve_signature_name(signature_name))

    public_key = signer.generate_keypair()

    return signer, public_key


def sign_payload(signature_name, message_bytes):

    signer = oqs.Signature(resolve_signature_name(signature_name))

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

    verifier = oqs.Signature(resolve_signature_name(signature_name))

    signature = base64.b64decode(signature_b64)

    public_key = base64.b64decode(public_key_b64)

    verified = verifier.verify(
        message_bytes,
        signature,
        public_key
    )
    print("Verification Result:", verified)
    return verified
# ----------------------------------------
# Classical Signatures (ECDSA)
# ----------------------------------------

def classical_keygen():

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def classical_sign(private_key, message_bytes):

    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )

    return {
        "signature": base64.b64encode(signature).decode(),

        "public_key": base64.b64encode(
            private_key.public_key().public_bytes(
                Encoding.X962,
                PublicFormat.UncompressedPoint
            )
        ).decode()
    }


def classical_verify(
        public_key_b64,
        signature_b64,
        message_bytes):

    try:

        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            base64.b64decode(public_key_b64)
        )

        public_key.verify(
            base64.b64decode(signature_b64),
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except InvalidSignature:

        return False

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