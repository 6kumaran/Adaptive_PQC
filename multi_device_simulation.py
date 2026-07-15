from iot_device import IoTDevice
from decision_engine import decide_execution
from ml_decision_engine import ml_decide_execution
from pqc_module import kyber_keygen, kyber_encrypt, kyber_decrypt, resolve_signature_name
import requests
import time, os
import random
from quantum_readiness import calculate_quantum_readiness

EDGE_SERVER_URL = os.getenv(
    "EDGE_SERVER_URL",
    "http://127.0.0.1:8000/offload"
)

CONTEXT_PROFILES = [
    "BALANCED",
    "HIGH_SECURITY",
    "PERFORMANCE",
    "ENERGY_SAVING",
    "MISSION_CRITICAL",
]

EDGE_STATUS = [
    "AVAILABLE",
    "BUSY",
    "OVERLOADED",
]

# -----------------------------------
# Multi-Edge Simulator
# -----------------------------------
def simulate_edge_nodes(num_edges=3):
    """
    Simulates multiple edge servers for a device.
    Stage 1 only generates edge information.
    No edge selection is performed yet.
    """

    edges = []

    for i in range(num_edges):

        edge = {
            "edge_id": f"EDGE-{i + 1}",
            "cpu": random.randint(15, 90),
            "memory": random.randint(20, 95),
            "latency": random.randint(5, 80),
            "load": round(random.uniform(0.10, 1.00), 2),
            "status": random.choice(EDGE_STATUS),
        }

        edges.append(edge)

    return edges
# -----------------------------------
# Edge Load Balancer
# -----------------------------------
def select_best_edge(available_edges):
    """
    Selects the best edge using a simple priority strategy.

    Priority:
    1. AVAILABLE
    2. BUSY
    3. OVERLOADED

    Within each priority group, the lowest weighted
    resource score is selected.
    """

    priority_groups = [
        "AVAILABLE",
        "BUSY",
        "OVERLOADED",
    ]

    for status in priority_groups:

        candidates = [
            edge for edge in available_edges
            if edge["status"] == status
        ]

        if not candidates:
            continue

        best_edge = None
        best_score = float("inf")

        for edge in candidates:

            score = (
                edge["cpu"] * 0.35 +
                edge["memory"] * 0.25 +
                edge["latency"] * 0.25 +
                (edge["load"] * 100) * 0.15
            )

            edge["score"] = round(score, 2)
            edge["selected"] = False

            if score < best_score:
                best_score = score
                best_edge = edge

        best_edge["selected"] = True
        return best_edge

    return None
# -----------------------------------
# Single Device Execution
# -----------------------------------
def execute_device(device_id, use_ml=False):

    device = IoTDevice()
    status = device.get_device_status()
    # available_edges = simulate_edge_nodes()
    # selected_edge = select_best_edge(
    #     available_edges
    # )
    context_profile = random.choice(
        CONTEXT_PROFILES
    )

    if use_ml:
        decision = ml_decide_execution(status,context_profile=context_profile)
    else:
        decision = decide_execution(status,context_profile=context_profile)

    mode = decision["execution"]
    kem = decision["kem"]
    signature = resolve_signature_name(decision["signature"])

    start = time.time()

    if mode == "edge":

        # Simulate edge execution latency
        time.sleep(0.003)
    else:
        kem_obj, pk = kyber_keygen()
        ct, ss1 = kyber_encrypt(kem_obj, pk)
        ss2 = kyber_decrypt(kem_obj, ct)

    end = time.time()

    result = {
    "device_id": device_id,

    "battery": status["battery"],
    "cpu": status["cpu"],
    "memory": status["memory"],
    "network": status["network"],

    "execution": decision["execution"],
    "mode": decision["mode"],

    "security_strategy": decision["security_strategy"],

    "kem_used": decision["kem"],
    "signature_used": decision["signature"],

    "execution_time_ms": round((end - start) * 1000, 2),

    "threat_profile": decision["threat_profile"],
    "threat_score": decision["threat_score"],
    "threat_level": decision["threat_level"],
    "threat_override": decision["threat_override"],

    "context_profile": decision["context_profile"],
    "context_priority": decision["context_priority"],
    "context_description": decision["context_description"],

    "estimated_energy": decision["estimated_energy"],
    "cpu_energy": decision["cpu_energy"],
    "memory_energy": decision["memory_energy"],
    "crypto_energy": decision["crypto_energy"],
    "signature_energy": decision["signature_energy"],
    "communication_energy": decision["communication_energy"],
    "energy_level": decision["energy_level"],
    "predicted_latency_ms":
        decision["predicted_latency_ms"],

    "latency_category":
        decision["latency_category"],

    "latency_optimization":
        decision["latency_optimization"],

    "latency_reason":
        decision["latency_reason"],
    # "available_edges": available_edges,
    # "selected_edge": selected_edge["edge_id"],

    # "edge_score": selected_edge["score"],
    
    # "edge_cpu": selected_edge["cpu"],
    
    # "edge_memory": selected_edge["memory"],
    
    # "edge_latency": selected_edge["latency"],
    
    # "edge_load": selected_edge["load"],
    
    # "edge_status": selected_edge["status"],
    
    # "load_balancing_reason":
    #     "Lowest weighted resource score",
    }
    assessment = calculate_quantum_readiness(result)

    result.update(assessment)

    return result

# -----------------------------------
# Multi Device Simulation
# -----------------------------------
def simulate_devices(
    n_devices=10,
    use_ml=False,
    simulation_mode=False,
):

    results = []

    for i in range(n_devices):

        result = execute_device(i, use_ml)

        if simulation_mode and result["execution"] == "edge":

            available_edges = simulate_edge_nodes()

            selected_edge = select_best_edge(
                available_edges
            )

            result["available_edges"] = available_edges

            result["selected_edge"] = selected_edge["edge_id"]

            result["edge_score"] = selected_edge["score"]

            result["edge_cpu"] = selected_edge["cpu"]

            result["edge_memory"] = selected_edge["memory"]

            result["edge_latency"] = selected_edge["latency"]

            result["edge_load"] = selected_edge["load"]

            result["edge_status"] = selected_edge["status"]

            result["load_balancing_reason"] = (
                "Lowest weighted resource score"
            )

        results.append(result)

    return results

# ---------- TEST ----------
if __name__ == "__main__":

    results = simulate_devices(
        10,
        use_ml=False,
        simulation_mode=True,
    )

    for r in results:
        print(r)