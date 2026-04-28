from functools import lru_cache
from pathlib import Path
import argparse
import os


DEFAULT_ARTIFACTS_DIR = (
    Path(__file__).resolve().parents[1]
    / "ML"
    / "Windows"
    / "trained_models"
    / "training_meta_data"
)


@lru_cache(maxsize=1)
def get_artifacts(artifacts_dir: str | None = None):
    from ML.Windows.preprocess_inference import load_artifacts

    path = Path(
        artifacts_dir
        or os.getenv("SOC_ML_ARTIFACTS_DIR")
        or DEFAULT_ARTIFACTS_DIR
    )
    return load_artifacts(path)


def predict_with_original_data(df_raw, artifacts=None):
    from ML.Windows.preprocess_inference import predict

    df_out = df_raw.copy()
    model_artifacts = artifacts or get_artifacts()
    df_out["ML_prediction"] = predict(df_raw, model_artifacts)
    return df_out


def main() -> int:
    import pandas as pd

    parser = argparse.ArgumentParser(description="Run the Windows ML predictor")
    parser.add_argument("--input", required=True, help="Path to a CSV file")
    parser.add_argument("--output", help="Optional path to save enriched CSV")
    parser.add_argument(
        "--artifacts",
        help="Path to ML artifact directory (defaults to the repo copy)",
    )
    args = parser.parse_args()

    df_raw = pd.read_csv(args.input, low_memory=False)
    df_out = predict_with_original_data(df_raw, get_artifacts(args.artifacts))

    if args.output:
        df_out.to_csv(args.output, index=False)
    else:
        print(df_out.to_json(orient="records", indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())