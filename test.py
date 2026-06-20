from ml_decision_engine import ml_decide_execution

test = {
    "battery": 15,
    "cpu": 15,
    "memory": 15,
    "network": "poor"
}

print(ml_decide_execution(test))