"""
Run model inference on new CIC-IDS2017-style data using saved preprocessing artifacts.

Adjust the paths in the CONFIG section for Kaggle:
- Inputs usually live under /kaggle/input/<dataset-name>/...
- Outputs you create should go under /kaggle/working/...
"""

from pathlib import Path

import joblib
import pandas as pd

from preprocess import preprocess


# -------------------------------
# CONFIG: update these paths
# -------------------------------
# the new incoming data
RAW_DATA_PATH = Path("new_data.csv")

# the model you want to use
MODEL_PATH = Path("/trained_Models/best_model/RandomForest_Model2.joblib")

# Preprocessing artifacts saved from the notebook
ARTIFACT_DIR = Path("/trained_Models/training_data")
SCALER_PATH = ARTIFACT_DIR / "scaler.pkl"
IPCA_PATH = ARTIFACT_DIR / "ipca.pkl"
META_PATH = ARTIFACT_DIR / "training_meta.pkl"

# Optional: where to save predictions
OUTPUT_PATH = Path("/output/predictions.csv")


def main() -> None:
    if not RAW_DATA_PATH.exists():
        raise FileNotFoundError(f"Missing input file: {RAW_DATA_PATH}")
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Missing model file: {MODEL_PATH}")
    for p in (SCALER_PATH, IPCA_PATH, META_PATH):
        if not p.exists():
            raise FileNotFoundError(f"Missing preprocessing artifact: {p}")

    scaler = joblib.load(SCALER_PATH)
    ipca = joblib.load(IPCA_PATH)
    training_meta = joblib.load(META_PATH)
    model = joblib.load(MODEL_PATH)

    raw = pd.read_csv(RAW_DATA_PATH)
    X_ready = preprocess(raw, scaler, ipca, training_meta)

    preds = model.predict(X_ready)
    out = pd.DataFrame({"prediction": preds})
    out.to_csv(OUTPUT_PATH, index=False)

    print(f"Saved predictions to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
