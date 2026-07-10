"""
Energy Consumption Modeling Module
----------------------------------
Provides normalized energy estimation for adaptive
security decisions in the Adaptive PQC framework.

The estimated values are simulation coefficients intended
for comparative analysis of security strategies and are
not direct physical power measurements.
"""

from typing import Dict
from typing import Any


# ==========================================================
# Relative Energy Cost Tables (Normalized Simulation Values)
# ==========================================================

KEM_ENERGY_COEFFICIENT = {
    "CLASSICAL": 1.0,
    "ML-KEM-512": 2.5,
    "ML-KEM-768": 3.5,
    "ML-KEM-1024": 4.5,
    "FrodoKEM-640-AES": 6.0,
}

SIGNATURE_ENERGY_COEFFICIENT = {
    "None": 0.0,
    "Dilithium2": 1.5,
    "Dilithium3": 2.0,
    "SPHINCS+-SHAKE-128f-simple": 4.5,
}

STRATEGY_MULTIPLIER = {
    "CLASSICAL": 1.0,
    "PQC": 1.25,
    "HYBRID": 1.60,
}


# ==========================================================
# Private Helper Functions
# ==========================================================

def _estimate_cpu_energy(cpu_usage: float) -> float:
    """
    Estimate CPU energy contribution.

    Range:
        0 - 100 % CPU
        ≈ 0.5 - 5.0 mJ
    """

    cpu_usage = max(0.0, min(cpu_usage, 100.0))

    return round(0.5 + (cpu_usage / 100.0) * 4.5, 2)


def _estimate_crypto_energy(
    kem_algorithm: str,
    security_strategy: str,
) -> float:
    """
    Estimate KEM energy.
    """

    base = KEM_ENERGY_COEFFICIENT.get(kem_algorithm, 2.5)

    multiplier = STRATEGY_MULTIPLIER.get(
        security_strategy,
        1.0,
    )

    return round(base * multiplier, 2)


def _estimate_signature_energy(signature_algorithm: str) -> float:
    """
    Estimate digital signature energy.
    """

    return round(
        SIGNATURE_ENERGY_COEFFICIENT.get(
            signature_algorithm,
            2.0,
        ),
        2,
    )


def _estimate_communication_energy(
    network_quality: str,
    execution_location: str,
) -> float:
    """
    Estimate communication energy.

    Edge execution incurs network overhead.
    """

    network_quality = network_quality.lower()

    if execution_location == "local":
        return 0.50

    base = {
        "excellent": 1.0,
        "good": 1.5,
        "moderate": 2.5,
        "poor": 4.0,
    }.get(network_quality, 2.5)

    return round(base, 2)


def _estimate_memory_energy(memory_usage: float) -> float:
    """
    Estimate memory contribution.

    Range:
        0.3 - 2.0 mJ
    """

    memory_usage = max(0.0, min(memory_usage, 100.0))

    return round(
        0.3 + (memory_usage / 100.0) * 1.7,
        2,
    )


def _classify_energy_level(total_energy: float) -> str:
    """
    Classify overall energy consumption.
    """

    if total_energy < 8:
        return "LOW"

    if total_energy < 15:
        return "MEDIUM"

    return "HIGH"


# ==========================================================
# Public API
# ==========================================================

def estimate_energy(
    cpu_usage: float,
    memory_usage: float,
    network_quality: str,
    security_strategy: str,
    kem_algorithm: str,
    signature_algorithm: str,
    execution_location: str,
) -> Dict[str, Any]:
    """
    Estimate total energy consumption.

    Returns
    -------
    Dictionary containing individual energy components
    and total estimated energy.
    """

    cpu_energy = _estimate_cpu_energy(cpu_usage)

    memory_energy = _estimate_memory_energy(
        memory_usage
    )

    crypto_energy = _estimate_crypto_energy(
        kem_algorithm,
        security_strategy,
    )

    signature_energy = _estimate_signature_energy(
        signature_algorithm
    )

    communication_energy = _estimate_communication_energy(
        network_quality,
        execution_location,
    )

    total_energy = round(
        cpu_energy
        + memory_energy
        + crypto_energy
        + signature_energy
        + communication_energy,
        2,
    )

    return {
        "estimated_energy": total_energy,
        "cpu_energy": cpu_energy,
        "memory_energy": memory_energy,
        "crypto_energy": crypto_energy,
        "signature_energy": signature_energy,
        "communication_energy": communication_energy,
        "energy_level": _classify_energy_level(
            total_energy
        ),
    }


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    result = estimate_energy(
        cpu_usage=42.5,
        memory_usage=61.2,
        network_quality="good",
        security_strategy="PQC",
        kem_algorithm="ML-KEM-768",
        signature_algorithm="Dilithium3",
        execution_location="edge",
    )

    print("\nEstimated Energy Model\n")

    for key, value in result.items():
        print(f"{key:25}: {value}")