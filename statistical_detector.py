import pandas as pd


def compute_baseline_parameters(series, mode="mean_std"):
    """
    Computes location and dispersion scale parameters for a numeric series.
    
    Modes:
      - 'mean_std': center = mean, scale = std
      - 'median_mad': center = median, scale = 1.4826 * MAD (Median Absolute Deviation)
    """
    clean_series = pd.to_numeric(series, errors="coerce").dropna()
    if clean_series.empty:
        return 0.0, 0.0

    if mode == "median_mad":
        center = float(clean_series.median())
        mad = float((clean_series - center).abs().median())
        scale = float(1.4826 * mad)
    else:  # default 'mean_std'
        center = float(clean_series.mean())
        scale = float(clean_series.std())

    return center, scale


def detect_statistical_anomalies(
    df,
    std_multiplier=2.0,
    baseline_mode="mean_std",
    column="packets",
):
    """
    Performs statistical network traffic anomaly detection.

    Parameters:
      df: pandas DataFrame containing network data
      std_multiplier: float, multiplier above baseline to flag anomalies (default 2.0)
      baseline_mode: 'mean_std' (default) or 'median_mad' (robust MAD)
      column: column to test for anomaly (default 'packets')

    Returns:
      status_series: pd.Series of 'Potential Anomaly' / 'Normal'
      threshold: float threshold value used
    """
    if column not in df.columns:
        raise ValueError(f"Column '{column}' not found in DataFrame.")

    clean_series = pd.to_numeric(df[column], errors="coerce")
    center, scale = compute_baseline_parameters(clean_series, mode=baseline_mode)

    if pd.isna(scale) or scale == 0:
        threshold = float("inf")
    else:
        threshold = center + (std_multiplier * scale)

    status_series = clean_series.apply(
        lambda x: "Potential Anomaly" if pd.notna(x) and x > threshold else "Normal"
    )

    return status_series, threshold
