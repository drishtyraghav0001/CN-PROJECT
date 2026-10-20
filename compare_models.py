
import pandas as pd

from data_loader import load_network_data
from ml_detector import detect_anomalies

# Load network traffic data
df = load_network_data("network_traffic.json")

# Existing statistical method
mean = df["packets"].mean()
std = df["packets"].std()

threshold = mean + 2 * std

df["statistical_status"] = df["packets"].apply(
    lambda x: "Potential Anomaly"
    if x > threshold else "Normal"
)

# Machine-learning method
ml_results = detect_anomalies(df)

df["ml_status"] = ml_results["ml_status"]

# Display comparison
print("\nMODEL COMPARISON")
print("=" * 65)

print(df[[
    "protocol",
    "packets",
    "statistical_status",
    "ml_status"
]].to_string(index=False))

print("\nStatistical method:")
print(df["statistical_status"].value_counts())

print("\nMachine-learning method:")
print(df["ml_status"].value_counts())

