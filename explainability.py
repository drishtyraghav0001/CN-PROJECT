import pandas as pd


FEATURE_NAME_MAP = {
    "packets": "packet count",
    "bytes": "bytes",
    "duration": "duration",
    "source_port": "source port",
    "packets_per_sec": "packets per second",
    "bytes_per_sec": "bytes per second",
    "bytes_per_packet": "bytes per packet",
}


def format_feature_name(feature):
    """Returns the readable display name for a network feature."""
    lower = str(feature).strip().lower()
    return FEATURE_NAME_MAP.get(lower, lower.replace("_", " "))


def compute_baseline_stats(df, columns=None, baseline_mode="mean_std"):
    """
    Computes baseline statistics per available numeric column from the loaded dataset.
    
    Modes:
      - 'mean_std' (default): center = mean, dispersion = std dev
      - 'median_mad': center = median, dispersion = 1.4826 * MAD (robust)

    Skips features with zero dispersion, missing values, or non-numeric types
    to avoid division by zero.
    """
    if columns is None:
        exclude = {
            "protocol",
            "ml_result",
            "ml_status",
            "statistical_status",
            "statistical result",
            "ml result",
            "flagged by",
            "reasons",
            "flagged_by",
        }
        candidates = [
            "packets",
            "bytes",
            "duration",
            "source_port",
            "packets_per_sec",
            "bytes_per_sec",
            "bytes_per_packet",
        ]
        cand_present = [c for c in candidates if c in df.columns]
        other_numeric = [
            c
            for c in df.columns
            if c.lower() not in exclude
            and c not in cand_present
            and pd.api.types.is_numeric_dtype(df[c])
        ]
        columns = cand_present + other_numeric

    baseline = {}
    for col in columns:
        if col not in df.columns:
            continue
        series = pd.to_numeric(df[col], errors="coerce").dropna()
        if series.empty:
            continue

        if baseline_mode == "median_mad":
            center_val = float(series.median())
            scale_val = float(1.4826 * (series - center_val).abs().median())
        else:  # default 'mean_std'
            center_val = float(series.mean())
            scale_val = float(series.std())

        if pd.isna(scale_val) or scale_val == 0 or pd.isna(center_val):
            continue

        baseline[col] = {
            "mean": center_val,
            "std": scale_val,
            "center": center_val,
            "scale": scale_val,
            "mode": baseline_mode,
        }

    return baseline


def find_deviations(record, baseline_stats, threshold=2.0):
    """
    For a single record (dict-like or pandas Series), finds which features deviate
    from the baseline (z-score magnitude >= threshold, default 2.0) and in which
    direction ('high' or 'low').
    """
    deviations = []
    for feature, stats in baseline_stats.items():
        if feature not in record:
            continue
        val = record[feature]
        try:
            val_num = float(val)
        except (ValueError, TypeError):
            continue
        if pd.isna(val_num):
            continue

        mean = stats["mean"]
        std = stats["std"]
        if std == 0 or pd.isna(std):
            continue

        z_score = (val_num - mean) / std
        if abs(z_score) >= threshold:
            direction = "high" if z_score > 0 else "low"
            deviations.append({
                "feature": feature,
                "value": val_num,
                "mean": mean,
                "std": std,
                "z_score": z_score,
                "abs_z": abs(z_score),
                "direction": direction,
            })

    return deviations


def format_reason(deviations):
    """
    Turns feature deviations into a human-readable reason string.
    e.g. "Packet count 4.1 std above baseline; bytes 3.2 std above baseline"
    """
    if not deviations:
        return ""

    parts = []
    for i, dev in enumerate(deviations):
        name = format_feature_name(dev["feature"])
        if i == 0:
            name = name[0].upper() + name[1:] if name else name
        else:
            name = name.lower()

        dir_str = "above baseline" if dev["direction"] == "high" else "below baseline"
        parts.append(f"{name} {dev['abs_z']:.1f} std {dir_str}")

    return "; ".join(parts)


def get_flagged_by(statistical_result, ml_result):
    """
    Returns which detection method(s) flagged the record:
    'Statistical', 'ML', 'Both', or 'None'.
    """
    if isinstance(statistical_result, bool):
        stat_flagged = statistical_result
    else:
        stat_flagged = str(statistical_result).strip().lower() in (
            "potential anomaly",
            "anomaly",
            "flagged",
            "true",
            "1",
        )

    if isinstance(ml_result, bool):
        ml_flagged = ml_result
    else:
        ml_flagged = str(ml_result).strip().lower() in (
            "potential anomaly",
            "anomaly",
            "flagged",
            "true",
            "1",
        )

    if stat_flagged and ml_flagged:
        return "Both"
    elif stat_flagged:
        return "Statistical"
    elif ml_flagged:
        return "ML"
    else:
        return "None"


def explain_record(record, baseline_stats, threshold=2.0, stat_status=None, ml_status=None):
    """
    Explains a single record by finding deviations, formatting reasons,
    and determining the flagging method(s).
    """
    deviations = find_deviations(record, baseline_stats, threshold=threshold)
    reasons = format_reason(deviations)

    s_val = (
        stat_status
        if stat_status is not None
        else record.get("Statistical Result", record.get("statistical_status", "Normal"))
    )
    m_val = (
        ml_status
        if ml_status is not None
        else record.get("ML Result", record.get("ml_status", "Normal"))
    )
    flagged_by = get_flagged_by(s_val, m_val)

    return {
        "flagged_by": flagged_by,
        "deviations": deviations,
        "reasons": reasons if flagged_by != "None" else "",
    }


def compute_severity(flagged_by, n_deviations):
    """
    Computes anomaly severity based on method agreement and feature deviation count:
      - High: Flagged by both methods AND at least 3 features deviate
      - Medium: Flagged by both methods OR at least 2 features deviate
      - Low: Single-method detection with 1 feature deviation
      - Normal: Unflagged records
    """
    if flagged_by == "None" or not flagged_by:
        return "Normal"

    is_both = (flagged_by == "Both")
    if is_both and n_deviations >= 3:
        return "High"
    elif is_both or n_deviations >= 2:
        return "Medium"
    else:
        return "Low"


def add_explanations(df, threshold=2.0, baseline_mode="mean_std"):
    """
    Computes baseline statistics and adds 'Flagged By', 'Severity', and 'Reasons'
    columns to the given dataframe using the specified baseline_mode.
    """
    baseline = compute_baseline_stats(df, baseline_mode=baseline_mode)
    stat_col = (
        "Statistical Result"
        if "Statistical Result" in df.columns
        else ("statistical_status" if "statistical_status" in df.columns else None)
    )
    ml_col = (
        "ML Result"
        if "ML Result" in df.columns
        else ("ml_status" if "ml_status" in df.columns else None)
    )

    flagged_by_list = []
    reasons_list = []
    severity_list = []

    for _, row in df.iterrows():
        s_val = row[stat_col] if stat_col else "Normal"
        m_val = row[ml_col] if ml_col else "Normal"
        fb = get_flagged_by(s_val, m_val)
        flagged_by_list.append(fb)

        if fb != "None":
            devs = find_deviations(row, baseline, threshold=threshold)
            reasons_list.append(format_reason(devs))
            severity_list.append(compute_severity(fb, len(devs)))
        else:
            reasons_list.append("")
            severity_list.append("Normal")

    df["Flagged By"] = flagged_by_list
    df["Severity"] = severity_list
    df["Reasons"] = reasons_list
    return df


# Aliases for flexibility
calculate_baseline_stats = compute_baseline_stats
get_baseline_stats = compute_baseline_stats
format_reasons = format_reason
determine_flagged_by = get_flagged_by
explain_dataframe = add_explanations
explain_dataset = add_explanations
generate_explanations = add_explanations
