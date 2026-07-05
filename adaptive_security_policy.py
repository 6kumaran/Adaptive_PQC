"""
Adaptive Security Policy

Shared security policy used by both:

- Rule-Based Decision Engine
- ML Decision Engine

Only this file determines:

- Security Strategy
- KEM
- Signature
- Threat Override
- Context Metadata
"""

from context_profiles import get_context_profile


def apply_security_policy(
    battery,
    cpu,
    memory,
    execution,
    mode,
    threat_data,
    context_profile="BALANCED"
):

    profile = get_context_profile(context_profile)

    threat_level = threat_data["threat_level"]

    threat_override = False

    security_mode = mode

    # ------------------------------------
    # Threat Override
    # ------------------------------------

    if threat_level == "LOW":

        if security_mode == "performance":
            security_mode = "balanced"

    elif threat_level == "MEDIUM":

        security_mode = "high_security"

    elif threat_level == "HIGH":

        security_mode = "high_security"

    if security_mode != mode:
        threat_override = True

    # ------------------------------------
    # Security Strategy
    # ------------------------------------

    if threat_level == "SAFE":

        security_strategy = "CLASSICAL"

    elif threat_level in ["LOW", "MEDIUM"]:

        security_strategy = "PQC"

    else:

        security_strategy = "HYBRID"

    # ------------------------------------
    # KEM Selection
    # ------------------------------------

    if security_mode == "performance":

        kem = "ML-KEM-512"

    elif security_mode == "balanced":

        kem = "ML-KEM-768"

    else:

        kem = "ML-KEM-1024"

    if memory > 70 and cpu < 60:

        kem = "FrodoKEM-640-AES"

    if threat_level == "HIGH":

        kem = "ML-KEM-1024"

    # ------------------------------------
    # Signature
    # ------------------------------------

    if security_mode == "performance":

        signature = "Dilithium2"

    elif security_mode == "balanced":

        signature = "Dilithium3"

    else:

        signature = "SPHINCS+-SHAKE-128f-simple"

    if threat_level == "HIGH":

        signature = "SPHINCS+-SHAKE-128f-simple"

    return {

        "execution": execution,

        "mode": security_mode,

        "security_strategy": security_strategy,

        "kem": kem,

        "signature": signature,

        "threat_override": threat_override,

        "context_profile": context_profile,

        "context_priority":
            profile["priority"],

        "context_description":
            profile["description"]
    }