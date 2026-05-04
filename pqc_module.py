import oqs

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

    
    
    
    
    
    import oqs

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