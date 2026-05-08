import random
import pandas as pd
from decision_engine import decide_execution
import joblib
from sklearn.ensemble import RandomForestClassifier

# -----------------------------------
# Generate Synthetic Dataset
# -----------------------------------

data = []

network_map = {
    "good": 2,
    "moderate": 1,
    "poor": 0
}

for _ in range(5000):
    battery = random.uniform(0, 100)
    cpu = random.uniform(0, 100)
    memory = random.uniform(0, 100)
    network = random.choice(["good", "moderate", "poor"])

    status = {
        "battery": battery,
        "cpu": cpu,
        "memory": memory,
        "network": network
    }

    decision = decide_execution(status)

    data.append({
        "battery": battery,
        "cpu": cpu,
        "memory": memory,
        "network": network_map[network],
        "execution": decision["execution"],
        "mode": decision["mode"]
    })

df = pd.DataFrame(data)

# -----------------------------------
# Encode Labels
# -----------------------------------

df["execution"] = df["execution"].map({"local": 1, "edge": 0})
df["mode"] = df["mode"].map({
    "performance": 0,
    "balanced": 1,
    "high_security": 2
})

X = df[["battery", "cpu", "memory", "network"]]
y_exec = df["execution"]
y_mode = df["mode"]

# -----------------------------------
# Train Models
# -----------------------------------

model_exec = RandomForestClassifier()
model_mode = RandomForestClassifier()

model_exec.fit(X, y_exec)
model_mode.fit(X, y_mode)

# -----------------------------------
# Save Models
# -----------------------------------

joblib.dump(model_exec, "model_execution.pkl")
joblib.dump(model_mode, "model_mode.pkl")

print("✅ Models trained and saved")