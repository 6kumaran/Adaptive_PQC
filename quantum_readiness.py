"""
Quantum Readiness Assessment Engine
-----------------------------------

Evaluates how well the current adaptive security
configuration prepares an IoT device for deployment
in a post-quantum environment.

This module DOES NOT influence decision making.

It only evaluates the final execution result.
"""

from typing import Dict, Any


# ==========================================================
# Component Weights
# ==========================================================

CRYPTO_WEIGHT = 30
SECURITY_WEIGHT = 20
RESOURCE_WEIGHT = 15
NETWORK_WEIGHT = 10
ENERGY_WEIGHT = 10
EXECUTION_WEIGHT = 10
CONTEXT_WEIGHT = 5


# ==========================================================
# Readiness Profiles
# ==========================================================

ENERGY_PROFILE = {
    "LOW": 10,
    "MEDIUM": 7,
    "HIGH": 4
}

LATENCY_PROFILE = {
    "LOW": 10,
    "MODERATE": 8,
    "HIGH": 5,
    "CRITICAL": 2
}

CONTEXT_PROFILE = {
    "MISSION_CRITICAL": 5,
    "HIGH_SECURITY": 5,
    "BALANCED": 4,
    "PERFORMANCE": 3,
    "ENERGY_SAVING": 3
}


# ==========================================================
# Private Evaluation Functions
# ==========================================================

def _evaluate_crypto(
    strategy: str,
    kem: str,
    signature: str,
) -> int:

    score = 0

    # Security Strategy
    if strategy == "HYBRID":
        score += 12

    elif strategy == "PQC":
        score += 10

    else:
        score += 5

    # KEM
    kem_scores = {
        "ML-KEM-512": 5,
        "ML-KEM-768": 7,
        "ML-KEM-1024": 10,
        "FrodoKEM-640-AES": 10,
        "CLASSICAL": 2
    }

    score += kem_scores.get(kem, 5)

    # Signature
    signature_scores = {
        "Dilithium2": 5,
        "Dilithium3": 6,
        "SPHINCS+-SHAKE-128f-simple": 8,
        "None": 0
    }

    score += signature_scores.get(signature, 5)

    return min(score, CRYPTO_WEIGHT)


def _evaluate_security(
    threat_level: str,
    threat_override: bool,
    strategy: str,
) -> int:

    score = 0

    # Threat-aware adaptation
    if threat_level == "HIGH":

        if strategy == "HYBRID":
            score = 18

        elif strategy == "PQC":
            score = 15

        else:
            score = 8

    elif threat_level == "MEDIUM":

        score = 16 if strategy != "CLASSICAL" else 10

    else:

        score = 14

    # Reward adaptive override
    if threat_override:
        score += 2

    return min(score, SECURITY_WEIGHT)


def _evaluate_resources(
    battery: float,
    cpu: float,
    memory: float,
) -> int:

    score = 0

    if battery > 70:
        score += 5

    elif battery > 40:
        score += 3

    else:
        score += 1

    if cpu < 40:
        score += 5

    elif cpu < 75:
        score += 3

    else:
        score += 1

    if memory < 50:
        score += 5

    elif memory < 75:
        score += 3

    else:
        score += 1

    return min(score, RESOURCE_WEIGHT)


def _evaluate_network(category: str) -> int:

    return LATENCY_PROFILE.get(
        str(category).upper(),
        5
    )

def _evaluate_energy(level: str) -> int:

    return ENERGY_PROFILE.get(
        str(level).upper(),
        5
    )


def _evaluate_execution(
    execution: str,
) -> int:

    if execution == "edge":
        return 10

    return 8


def _evaluate_context(profile: str) -> int:

    return CONTEXT_PROFILE.get(
        str(profile).upper(),
        3
    )


# ==========================================================
# Recommendations
# ==========================================================

def _generate_recommendations(result):

    recommendations = []

    if result["security_strategy"] == "CLASSICAL":

        recommendations.append(
            "Consider migrating to PQC or Hybrid security."
        )

    if result["energy_level"] == "HIGH":

        recommendations.append(
            "Energy consumption is high. Consider an energy-saving profile."
        )

    if result["latency_category"] == "CRITICAL":

        recommendations.append(
            "Critical latency detected. Edge execution may experience delays."
        )

    if result["battery"] < 30:

        recommendations.append(
            "Low battery reduces sustained readiness."
        )

    if result["security_strategy"] == "HYBRID":

        recommendations.append(
            "Hybrid strategy provides excellent resilience."
        )

    if result["kem_used"] == "FrodoKEM-640-AES":

        recommendations.append(
            "FrodoKEM provides strong security with higher resource usage."
        )

    if not recommendations:

        recommendations.append(
            "Current configuration is well optimized."
        )

    return recommendations


# ==========================================================
# Readiness Level
# ==========================================================

def _readiness_level(score):

    if score >= 90:
        return "Excellent"

    if score >= 75:
        return "High"

    if score >= 60:
        return "Moderate"

    if score >= 40:
        return "Low"

    return "Poor"


# ==========================================================
# Public API
# ==========================================================

def calculate_quantum_readiness(result: Dict[str, Any]):

    crypto = _evaluate_crypto(
        result["security_strategy"],
        result["kem_used"],
        result["signature_used"]
    )

    security = _evaluate_security(
        result["threat_level"],
        result.get("threat_override", False),
        result["security_strategy"]
    )

    resources = _evaluate_resources(
        result["battery"],
        result["cpu"],
        result["memory"]
    )

    network = _evaluate_network(
        result.get("latency_category", "MODERATE")
    )

    energy = _evaluate_energy(
        result.get("energy_level", "MEDIUM")
    )

    execution = _evaluate_execution(
        result["execution"]
    )

    context = _evaluate_context(
        result["context_profile"]
    )

    total = (
        crypto
        + security
        + resources
        + network
        + energy
        + execution
        + context
    )

    return {

        "quantum_readiness_score": total,

        "quantum_readiness_level":
            _readiness_level(total),

        "assessment_version": "1.0",

        "component_scores": {

            "cryptography": crypto,
            "security": security,
            "resources": resources,
            "network": network,
            "energy": energy,
            "execution": execution,
            "context": context,
        },

        "recommendations":
            _generate_recommendations(result)
    }


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    sample = {

    "security_strategy": "HYBRID",

    "kem_used": "ML-KEM-1024",

    "signature_used": "SPHINCS+-SHAKE-128f-simple",

    "battery": 84,

    "cpu": 24,

    "memory": 36,

    "execution": "edge",

    "estimated_energy": 12.4,

    "energy_level": "LOW",

    "predicted_latency_ms": 41.7,

    "latency_category": "MODERATE",

    "threat_level": "HIGH",

    "threat_override": True,

    "context_profile": "MISSION_CRITICAL"
    }

    from pprint import pprint

    pprint(
        calculate_quantum_readiness(sample)
    )