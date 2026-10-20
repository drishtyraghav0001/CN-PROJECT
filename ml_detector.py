
import pandas as pd
from sklearn.ensemble import IsolationForest


def detect_anomalies(df):
    data = df.copy()

    # Select numerical features available in the dataset
    feature_candidates = [
        "packets",
        "bytes",
        "duration",
        "source_port"
    ]

    feature_cols = [
        col for col in feature_candidates
        if col in data.columns
    ]

    if not feature_cols:
        raise ValueError(
            "No numerical network traffic features found."
        )

    # Display information for debugging
    print("ML features used:", feature_cols)
    print("Number of records:", len(data))

    # Convert features to numeric values
    features = data[feature_cols].apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Handle missing or invalid values
    features = features.fillna(
        features.median()
    ).fillna(0)

    # Train the Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )

    predictions = model.fit_predict(features)

    # Save predictions in the output dataframe
    data["ml_result"] = predictions

    data["ml_status"] = data["ml_result"].map({
        1: "Normal",
        -1: "Potential Anomaly"
    })

    return data
