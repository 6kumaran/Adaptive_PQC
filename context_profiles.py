"""
Context Profiles
----------------
Defines the application context used by the Adaptive PQC Framework.

These profiles influence the adaptive security policy but
do NOT directly make security decisions.
"""

CONTEXT_PROFILES = {

    "BALANCED": {
        "display_name": "Balanced",
        "priority": "BALANCED",
        "security": 3,
        "performance": 3,
        "energy": 3,
        "description":
            "General-purpose adaptive security profile."
    },

    "HIGH_SECURITY": {
        "display_name": "High Security",
        "priority": "SECURITY",
        "security": 5,
        "performance": 2,
        "energy": 2,
        "description":
            "Maximum security for banking, healthcare and sensitive workloads."
    },

    "PERFORMANCE": {
        "display_name": "Performance",
        "priority": "PERFORMANCE",
        "security": 3,
        "performance": 5,
        "energy": 3,
        "description":
            "Optimized for low latency and high throughput."
    },

    "ENERGY_SAVING": {
        "display_name": "Energy Saving",
        "priority": "ENERGY",
        "security": 3,
        "performance": 3,
        "energy": 5,
        "description":
            "Optimized for battery-powered IoT devices."
    },

    "MISSION_CRITICAL": {
        "display_name": "Mission Critical",
        "priority": "RELIABILITY",
        "security": 5,
        "performance": 4,
        "energy": 2,
        "description":
            "Highest reliability and security for critical infrastructure."
    }

}


def get_context_profile(profile_name="BALANCED"):
    """
    Returns a validated context profile.
    """

    profile_name = profile_name.upper()

    return CONTEXT_PROFILES.get(
        profile_name,
        CONTEXT_PROFILES["BALANCED"]
    )


def list_context_profiles():
    """
    Returns available context names.
    """

    return list(CONTEXT_PROFILES.keys())