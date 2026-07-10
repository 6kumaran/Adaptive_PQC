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

SECURITY_POLICY_MATRIX = {

    "BALANCED": {
        "SAFE": "CLASSICAL",
        "LOW": "PQC",
        "MEDIUM": "PQC",
        "HIGH": "HYBRID"
    },

    "HIGH_SECURITY": {
        "SAFE": "PQC",
        "LOW": "PQC",
        "MEDIUM": "PQC",
        "HIGH": "HYBRID"
    },

    "PERFORMANCE": {
        "SAFE": "CLASSICAL",
        "LOW": "CLASSICAL",
        "MEDIUM": "PQC",
        "HIGH": "HYBRID"
    },

    "ENERGY_SAVING": {
        "SAFE": "CLASSICAL",
        "LOW": "CLASSICAL",
        "MEDIUM": "PQC",
        "HIGH": "HYBRID"
    },

    "MISSION_CRITICAL": {
        "SAFE": "PQC",
        "LOW": "PQC",
        "MEDIUM": "HYBRID",
        "HIGH": "HYBRID"
    }

}


def apply_security_policy(
    battery,
    cpu,
    memory,
    security_mode,
    threat_data,
    context_profile="PERFORMANCE"
):

    profile = get_context_profile(context_profile)

    threat_level = threat_data["threat_level"]

    threat_override = False

    original_security_mode = security_mode

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

    if security_mode != original_security_mode:
        threat_override = True

    # ------------------------------------
    # Context-Aware Security Strategy
    # ------------------------------------

    security_strategy = SECURITY_POLICY_MATRIX[
        context_profile
    ][
        threat_level
    ]

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

        "security_mode": security_mode,

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