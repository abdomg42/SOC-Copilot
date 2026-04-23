"""
preprocess.py
=============
Single `preprocess` function that transforms raw CIC-IDS2017 network-traffic
data into the exact format the trained ML models expect.

Pipeline (mirrors the notebook step-by-step):
  1. Strip whitespace from column names
  2. Drop duplicate rows
  3. Replace ±inf → NaN
  4. Fill NaN in 'Flow Bytes/s' and 'Flow Packets/s' with training medians
  5. Downcast float64 → float32  /  int64 → int32  (memory optimisation)
  6. Drop zero-variance columns (same columns removed during training)
  7. Drop label columns if present ('Label', 'Attack Type')
  8. Keep only the feature columns seen during training (same order)
  9. Apply the fitted StandardScaler
 10. Apply the fitted IncrementalPCA
 11. Return a DataFrame with columns PC1 … PCN

Usage
-----
Load your saved artefacts once, then call preprocess() for every new batch:

    import joblib
    scaler = joblib.load("scaler.pkl")
    ipca   = joblib.load("ipca.pkl")

    # Training metadata (save these when you train the model)
    training_meta = joblib.load("training_meta.pkl")
    # training_meta contains:
    #   "median_flow_bytes"   – float
    #   "median_flow_packets" – float
    #   "feature_columns"     – list[str]   (columns after dropping zero-var)
    #   "n_components"        – int         (PCA output width)

    import pandas as pd
    raw = pd.read_csv("new_traffic.csv")
    X_ready = preprocess(raw, scaler, ipca, training_meta)
    predictions = model.predict(X_ready)
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import IncrementalPCA


# ---------------------------------------------------------------------------
# Label columns that must be removed before feeding data to a model
# ---------------------------------------------------------------------------
_LABEL_COLS = {"Label", "Attack Type", "Attack Number"}


def preprocess(
    data: pd.DataFrame,
    scaler: StandardScaler,
    ipca: IncrementalPCA,
    training_meta: dict,
) -> pd.DataFrame:
    """
    Transform raw CIC-IDS2017 data into the format expected by the trained
    ML models.

    Parameters
    ----------
    data : pd.DataFrame
        Raw input rows.  May include label columns – they will be ignored.
    scaler : sklearn.preprocessing.StandardScaler
        The StandardScaler fitted on the training features.
    ipca : sklearn.decomposition.IncrementalPCA
        The IncrementalPCA fitted on the scaled training features.
    training_meta : dict
        Dictionary with the following keys (save these at training time):

        "median_flow_bytes"   : float
            Median of 'Flow Bytes/s' from the training set.
        "median_flow_packets" : float
            Median of 'Flow Packets/s' from the training set.
        "feature_columns"     : list[str]
            Ordered list of feature columns that survived zero-variance
            filtering during training (i.e. what was fed to StandardScaler).
        "n_components"        : int
            Number of PCA components (= len(feature_columns) // 2).

    Returns
    -------
    pd.DataFrame
        Shape (n_samples, n_components) with columns ['PC1', 'PC2', …, 'PCN'],
        ready to pass directly to model.predict() / model.predict_proba().

    Raises
    ------
    ValueError
        If a required key is missing from training_meta, or if feature columns
        expected by the scaler are absent from the input data.
    """

    # ── Validate training_meta ────────────────────────────────────────────
    required_keys = {"median_flow_bytes", "median_flow_packets",
                     "feature_columns", "n_components"}
    missing_keys = required_keys - set(training_meta.keys())
    if missing_keys:
        raise ValueError(
            f"training_meta is missing required keys: {missing_keys}\n"
            "Save these values when you train the model – see module docstring."
        )

    median_flow_bytes   = training_meta["median_flow_bytes"]
    median_flow_packets = training_meta["median_flow_packets"]
    feature_columns     = training_meta["feature_columns"]
    n_components        = training_meta["n_components"]

    # Work on a copy so we never mutate the caller's DataFrame
    df = data.copy()

    # ── Step 1: Strip whitespace from column names ────────────────────────
    df.rename(columns={col: col.strip() for col in df.columns}, inplace=True)

    # ── Step 2: Drop duplicate rows ───────────────────────────────────────
    df.drop_duplicates(inplace=True)

    # ── Step 3: Replace ±inf with NaN ────────────────────────────────────
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # ── Step 4: Fill NaN in the two affected columns with training medians ─
    for col, median_val in [
        ("Flow Bytes/s",   median_flow_bytes),
        ("Flow Packets/s", median_flow_packets),
    ]:
        if col in df.columns:
            df[col].fillna(median_val, inplace=True)

    # ── Step 5: Downcast dtypes to match training memory layout ───────────
    for col in df.columns:
        col_type = df[col].dtype
        if col_type == object:
            continue
        c_min, c_max = df[col].min(), df[col].max()

        if "float" in str(col_type):
            if c_min > np.finfo(np.float32).min and c_max < np.finfo(np.float32).max:
                df[col] = df[col].astype(np.float32)

        elif "int" in str(col_type):
            if c_min > np.iinfo(np.int32).min and c_max < np.iinfo(np.int32).max:
                df[col] = df[col].astype(np.int32)

    # ── Step 6 & 7: Drop label columns and zero-variance columns ──────────
    # Keep only the exact feature columns used during training (in the same
    # order).  This implicitly:
    #   • removes 'Label', 'Attack Type', 'Attack Number'
    #   • removes any zero-variance columns dropped during training
    missing_features = [c for c in feature_columns if c not in df.columns]
    if missing_features:
        raise ValueError(
            f"The following columns expected by the model are absent from the "
            f"input data:\n  {missing_features}\n"
            "Make sure you are passing the raw feature data before any manual "
            "column removal."
        )

    features = df[feature_columns]

    # ── Step 8 & 9: StandardScaler → IncrementalPCA ───────────────────────
    scaled   = scaler.transform(features)
    pca_out  = ipca.transform(scaled)

    # ── Step 10: Return a labelled DataFrame ──────────────────────────────
    pc_columns = [f"PC{i + 1}" for i in range(n_components)]
    result = pd.DataFrame(pca_out, columns=pc_columns, index=df.index)

    return result

