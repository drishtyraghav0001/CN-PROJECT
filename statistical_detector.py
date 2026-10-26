import math
import numpy as np
import pandas as pd

from feature_engineering import add_engineered_features

# Continuous network traffic measurement features (excluding categorical metadata like ports and IDs)
CONTINUOUS_TRAFFIC_FEATURES = [
    "packets",
    "bytes",
    "duration",
    "packets_per_sec",
    "bytes_per_sec",
    "bytes_per_packet",
]


class ThresholdResult(dict):
    """
    Holds per-feature statistical thresholds, baseline parameters, and settings.
    Inherits from dict for full mapping support while providing backward-compatible
    float formatting for callers that treat the threshold as a scalar (packet threshold).
    """

    def __init__(
        self,
        thresholds_dict,
        baseline_params=None,
        base_multiplier=2.0,
        effective_multiplier=2.0,
        baseline_mode="mean_std",
        bonferroni=True,
        primary_col="packets",
    ):
        super().__init__(thresholds_dict)
        self.baseline_params = baseline_params or {}
        self.base_multiplier = float(base_multiplier)
        self.effective_multiplier = float(effective_multiplier)
        self.baseline_mode = baseline_mode
        self.bonferroni = bonferroni
        self.primary_col = primary_col

    @property
    def primary_threshold(self):
        if self.primary_col in self:
            return self[self.primary_col]
        elif len(self) > 0:
            return next(iter(self.values()))
        return float("inf")

    def __float__(self):
        return float(self.primary_threshold)

    def __format__(self, format_spec):
        val = float(self)
        if val == float("inf"):
            return "inf"
        return format(val, format_spec)

    def __eq__(self, other):
        if isinstance(other, (int, float)):
            return float(self) == other
        return super().__eq__(other)

    def summary_text(self):
        parts = []
        for feat, thresh in self.items():
            if thresh == float("inf"):
                parts.append(f"{feat}: none (zero spread)")
            else:
                parts.append(f"{feat}: {thresh:,.2f}")
        return ", ".join(parts)


def compute_baseline_parameters(series, mode="mean_std"):
    """
    Computes location (center) and dispersion (scale) parameters for a numeric series.
    
    Modes:
      - 'mean_std': center = sample mean, scale = sample standard deviation
      - 'median_mad': center = sample median, scale = 1.4826 * MAD (Median Absolute Deviation)
    
    Non-finite values (inf, -inf) and NaNs are excluded.
    Returns (0.0, 0.0) if no valid finite values exist.
    """
    clean_series = pd.to_numeric(series, errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()
    if clean_series.empty:
        return 0.0, 0.0

    if mode == "median_mad":
        center = float(clean_series.median())
        mad = float((clean_series - center).abs().median())
        scale = float(1.4826 * mad)
    else:  # default 'mean_std'
        center = float(clean_series.mean())
        std_val = clean_series.std()
        scale = float(std_val) if pd.notna(std_val) else 0.0

    return center, scale


def calculate_bonferroni_multiplier(base_multiplier, n_features):
    """
    Computes Bonferroni-adjusted critical multiplier for testing n_features.
    
    Under a standard Gaussian assumption:
      alpha = 1 - Phi(base_multiplier)
      alpha_adj = alpha / n_features
      multiplier_adj = Phi^(-1)(1 - alpha_adj)
    
    If n_features <= 1 or base_multiplier <= 0, returns base_multiplier.
    """
    if n_features <= 1 or base_multiplier <= 0:
        return float(base_multiplier)

    try:
        from scipy.stats import norm
        alpha = float(norm.sf(base_multiplier))
        if alpha <= 0.0:
            return float(base_multiplier)
        alpha_adj = max(alpha / n_features, 1e-15)
        adj_mult = float(norm.isf(alpha_adj))
        return adj_mult
    except Exception:
        alpha = 0.5 * math.erfc(base_multiplier / math.sqrt(2.0))
        if alpha <= 0.0:
            return float(base_multiplier)
        alpha_adj = max(alpha / n_features, 1e-15)
        return float(base_multiplier * (1.0 + 0.15 * math.log(n_features)))


def detect_statistical_anomalies(
    df,
    std_multiplier=2.0,
    baseline_mode="mean_std",
    columns=None,
    column=None,
    bonferroni=True,
    two_sided=False,
    return_df=False,
):
    """
    Performs multi-feature statistical network traffic anomaly detection.

    Analyzes continuous numeric traffic features:
      - packets
      - bytes
      - duration
      - packets_per_sec (if engineered or calculable)
      - bytes_per_sec (if engineered or calculable)
      - bytes_per_packet (if engineered or calculable)

    Non-traffic metadata such as port numbers, protocol IDs, and IP addresses
    are excluded from continuous statistical testing.

    Threshold Interpretation:
      - 'mean_std':
          center = sample mean, scale = sample standard deviation.
          Under an approximate normal distribution heuristic, the Bonferroni-adjusted
          multiplier controls the family-wise false positive rate across multiple tests.
      - 'median_mad':
          center = sample median, scale = 1.4826 * MAD.
          Robust against existing outliers, with threshold = median + (multiplier * scale).

    Parameters:
      df: pandas DataFrame containing network traffic records (not mutated).
      std_multiplier: float, baseline multiplier to flag anomalies (default 2.0).
      baseline_mode: 'mean_std' (default) or 'median_mad' (robust MAD).
      columns: optional list of specific columns to evaluate.
      column: optional single column name for backward compatibility.
      bonferroni: bool, whether to adjust the threshold multiplier to control
                  the family-wise false alarm rate across tested features (default True).
      two_sided: bool, whether to flag both upper and lower deviations (default False:
                 upper-tail spikes only, matching network anomaly detection conventions).
      return_df: bool, whether to return an updated DataFrame copy instead of (Series, threshold).

    Returns:
      status_series: pd.Series of 'Potential Anomaly' / 'Normal' (or df if return_df=True).
      thresholds: ThresholdResult object containing per-feature thresholds and metadata.
    """
    if df.empty:
        empty_status = pd.Series(dtype=object, index=df.index)
        empty_res = ThresholdResult({}, base_multiplier=std_multiplier, baseline_mode=baseline_mode)
        return (df.copy(), empty_res) if return_df else (empty_status, empty_res)

    # Work on a copy to never mutate caller's original DataFrame
    working_df = df.copy()

    # If rate features are not yet present, generate them locally if base columns exist
    eng_candidates = ["packets_per_sec", "bytes_per_sec", "bytes_per_packet"]
    if not any(c in working_df.columns for c in eng_candidates):
        try:
            working_df = add_engineered_features(working_df)
        except Exception:
            pass

    # Resolve target candidate columns
    if columns is not None:
        if isinstance(columns, str):
            candidate_cols = [columns]
        else:
            candidate_cols = list(columns)
    elif column is not None:
        if isinstance(column, str):
            candidate_cols = [column]
        else:
            candidate_cols = list(column)
    else:
        candidate_cols = CONTINUOUS_TRAFFIC_FEATURES

    # Filter to columns that exist in the DataFrame
    present_cols = [c for c in candidate_cols if c in working_df.columns]

    if not present_cols:
        if column is not None and column not in working_df.columns:
            raise ValueError(f"Column '{column}' not found in DataFrame.")
        raise ValueError("No continuous numeric traffic features found in DataFrame for statistical detection.")

    # Select columns that contain usable finite numeric data
    usable_features = []
    numeric_series_map = {}
    for col in present_cols:
        s_num = pd.to_numeric(working_df[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
        clean_valid = s_num.dropna()
        if not clean_valid.empty:
            usable_features.append(col)
            numeric_series_map[col] = s_num

    if not usable_features:
        raise ValueError("No continuous traffic features contain usable numeric data.")

    # Determine effective multiplier with Bonferroni correction if enabled
    n_features = len(usable_features)
    if bonferroni and n_features > 1:
        effective_multiplier = calculate_bonferroni_multiplier(std_multiplier, n_features)
    else:
        effective_multiplier = float(std_multiplier)

    # Compute baseline parameters and thresholds for each usable feature
    thresholds_dict = {}
    baseline_params = {}
    for col in usable_features:
        s_num = numeric_series_map[col]
        center, scale = compute_baseline_parameters(s_num, mode=baseline_mode)
        baseline_params[col] = {"center": center, "scale": scale}

        # Safe handling: if scale is zero or NaN (constant feature or zero MAD),
        # threshold is inf so it never triggers an anomaly and division by zero is avoided.
        if pd.isna(scale) or scale <= 0.0:
            thresholds_dict[col] = float("inf")
        else:
            thresholds_dict[col] = center + (effective_multiplier * scale)

    # Evaluate records across features
    is_anomaly = pd.Series(False, index=df.index)
    triggered_features_per_row = [[] for _ in range(len(df))]
    deviations_per_row = [{} for _ in range(len(df))]

    for col in usable_features:
        thresh = thresholds_dict[col]
        if thresh == float("inf"):
            continue

        s_num = numeric_series_map[col]
        center = baseline_params[col]["center"]
        scale = baseline_params[col]["scale"]

        if two_sided and scale > 0.0:
            lower_thresh = center - (effective_multiplier * scale)
            col_flagged = s_num.notna() & np.isfinite(s_num) & ((s_num > thresh) | (s_num < lower_thresh))
        else:
            col_flagged = s_num.notna() & np.isfinite(s_num) & (s_num > thresh)

        is_anomaly = is_anomaly | col_flagged

        # Record triggered features and deviation details
        flagged_indices = np.where(col_flagged.values)[0]
        for idx in flagged_indices:
            val = float(s_num.iloc[idx])
            z = (val - center) / scale if scale > 0.0 else 0.0
            triggered_features_per_row[idx].append(col)
            deviations_per_row[idx][col] = {
                "value": val,
                "center": center,
                "scale": scale,
                "z_score": float(z),
                "threshold": thresh,
                "direction": "high" if val > center else "low",
            }

    status_series = is_anomaly.map({True: "Potential Anomaly", False: "Normal"})

    # Primary column preference for backward-compatible scalar threshold access
    primary_col = "packets" if "packets" in thresholds_dict else usable_features[0]

    thresh_result = ThresholdResult(
        thresholds_dict=thresholds_dict,
        baseline_params=baseline_params,
        base_multiplier=std_multiplier,
        effective_multiplier=effective_multiplier,
        baseline_mode=baseline_mode,
        bonferroni=bonferroni,
        primary_col=primary_col,
    )

    # Attach rich per-row metadata to status_series.attrs
    status_series.attrs["thresholds"] = thresh_result
    status_series.attrs["triggered_features"] = triggered_features_per_row
    status_series.attrs["deviations"] = deviations_per_row
    status_series.attrs["usable_features"] = usable_features

    if return_df:
        out_df = df.copy()
        out_df["Statistical Result"] = status_series.values
        out_df["Statistical Features"] = ["; ".join(f) if f else "" for f in triggered_features_per_row]
        return out_df, thresh_result

    return status_series, thresh_result

