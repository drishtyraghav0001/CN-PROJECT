
import pandas as pd
from sklearn.ensemble import IsolationForest


def detect_anomalies(df):
    data = df.copy()

    # Encode protocol names as numerical features
    data["protocol_code"] = (
        data["protocol"].astype("category").cat.codes
    )

    # Prepare model input
    features = data[["packets", "protocol_code"]]

    # Train an unsupervised anomaly detector
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )

    predictions = model.fit_predict(features)

    data["ml_result"] = predictions
    data["ml_status"] = data["ml_result"].map({
        1: "Normal",
        -1: "Potential Anomaly"
    })

    return data


if __name__ == "__main__":
    from data_loader import load_network_data

    df = load_network_data("network_traffic.json")
    result = detect_anomalies(df)

    print(result[["protocol", "packets", "ml_status"]])
    print("\nDetection summary:")
    print(result["ml_status"].value_counts())
