from ml_decision_engine import ml_decide_execution

test = {
    "battery": 65,
    "cpu": 30,
    "memory": 40,
    "network": "good"
}

print(ml_decide_execution(test))