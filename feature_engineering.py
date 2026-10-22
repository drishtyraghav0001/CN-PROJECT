import numpy as np
import pandas as pd


def add_engineered_features(df):
    """
    Computes and adds engineered traffic rate and volume features
    only when the required columns exist in the DataFrame.

    Engineered features:
      - packets_per_sec = packets / duration
      - bytes_per_sec = bytes / duration
      - bytes_per_packet = bytes / packets

    Validation rules:
      - duration <= 0, missing, or non-numeric: rate features become NaN.
        Never divides by zero and never treats missing as zero traffic.
      - packets <= 0 or missing: bytes_per_packet becomes NaN.
    """
    data = df.copy()

    has_packets = "packets" in data.columns
    has_bytes = "bytes" in data.columns
    has_duration = "duration" in data.columns

    p_series = pd.to_numeric(data["packets"], errors="coerce") if has_packets else None
    b_series = pd.to_numeric(data["bytes"], errors="coerce") if has_bytes else None
    d_series = pd.to_numeric(data["duration"], errors="coerce") if has_duration else None

    # Condition: duration > 0, numeric and not missing
    valid_duration = (d_series.notna() & (d_series > 0)) if has_duration else None

    # packets_per_sec = packets / duration
    if has_packets and has_duration:
        data["packets_per_sec"] = np.where(
            valid_duration & p_series.notna(),
            p_series / d_series,
            np.nan
        )

    # bytes_per_sec = bytes / duration
    if has_bytes and has_duration:
        data["bytes_per_sec"] = np.where(
            valid_duration & b_series.notna(),
            b_series / d_series,
            np.nan
        )

    # bytes_per_packet = bytes / packets
    if has_bytes and has_packets:
        valid_packets = p_series.notna() & (p_series > 0)
        data["bytes_per_packet"] = np.where(
            valid_packets & b_series.notna(),
            b_series / p_series,
            np.nan
        )

    return data
