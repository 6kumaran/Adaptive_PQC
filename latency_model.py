"""
Network Latency Prediction Module
---------------------------------
Provides realistic network latency estimation for the
Adaptive PQC Framework.

The values are simulation estimates intended for
adaptive decision making and analytics.
"""

from typing import Dict, Any

# ==========================================================
# Base Latency (ms)
# ==========================================================

BASE_NETWORK_LATENCY = {
    "good": 20,
    "moderate": 55,
    "poor": 100,
}


# ==========================================================
# Private Helpers
# ==========================================================

def _cpu_latency(cpu_usage: float) -> float:

    cpu_usage = max(0.0, min(cpu_usage, 100.0))

    return (cpu_usage / 100.0) * 20.0


def _memory_latency(memory_usage: float) -> float:

    memory_usage = max(0.0, min(memory_usage, 100.0))

    return (memory_usage / 100.0) * 10.0


def _execution_latency(execution_location: str) -> float:

    if execution_location.lower() == "edge":
        return 8.0

    return 0.0


def _classify_latency(latency: float) -> str:

    if latency < 30:
        return "LOW"

    if latency < 70:
        return "MODERATE"

    if latency < 120:
        return "HIGH"

    return "CRITICAL"


# ==========================================================
# Public API
# ==========================================================

def estimate_latency(
    cpu_usage: float,
    memory_usage: float,
    network_quality: str,
    execution_location: str,
) -> Dict[str, Any]:

    network_quality = network_quality.lower()

    base_latency = BASE_NETWORK_LATENCY.get(
        network_quality,
        55,
    )

    predicted_latency = (
        base_latency
        + _cpu_latency(cpu_usage)
        + _memory_latency(memory_usage)
        + _execution_latency(execution_location)
    )

    predicted_latency = round(
        max(predicted_latency, 1.0),
        2,
    )

    return {
        "predicted_latency_ms": predicted_latency,
        "latency_category": _classify_latency(
            predicted_latency
        ),
    }


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    result = estimate_latency(
        cpu_usage=42,
        memory_usage=58,
        network_quality="good",
        execution_location="edge",
    )

    print(result)