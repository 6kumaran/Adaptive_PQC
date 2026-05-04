import os
import json
import glob
import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# Load Results
# -----------------------------
files = glob.glob("results/*.json")

data = []

for file in files:
    with open(file, "r") as f:
        try:
            row = json.load(f)
            data.append(row)
        except:
            pass

if not data:
    print("No result files found.")
    exit()

df = pd.DataFrame(data)

print(df)

# -----------------------------
# Chart 1: Mode Count
# -----------------------------
plt.figure(figsize=(7,5))
df["mode"].value_counts().plot(kind="bar")
plt.title("Local vs Edge Executions")
plt.xlabel("Mode")
plt.ylabel("Count")
plt.tight_layout()
plt.show()

# -----------------------------
# Chart 2: KEM Frequency
# -----------------------------
plt.figure(figsize=(8,5))
df["kem_used"].value_counts().plot(kind="bar")
plt.title("KEM Algorithm Usage")
plt.xlabel("Algorithm")
plt.ylabel("Count")
plt.tight_layout()
plt.show()

# -----------------------------
# Chart 3: Execution Time
# -----------------------------
plt.figure(figsize=(8,5))
plt.plot(df["execution_time_ms"], marker="o")
plt.title("Execution Time Per Run")
plt.xlabel("Run Number")
plt.ylabel("Time (ms)")
plt.tight_layout()
plt.show()

# -----------------------------
# Chart 4: Avg Time by Mode
# -----------------------------
plt.figure(figsize=(7,5))
df.groupby("mode")["execution_time_ms"].mean().plot(kind="bar")
plt.title("Average Execution Time by Mode")
plt.ylabel("Time (ms)")
plt.tight_layout()
plt.show()