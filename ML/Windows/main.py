from __future__ import annotations

from .preprocess_inference import load_artifacts, preprocess


import ast
import json
import logging
import re
import warnings
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import joblib

from .preprocess_inference import _parse_args , predict

warnings.filterwarnings("ignore")

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

ARTIFACTS_DIR = Path(
    "/home/yassine/Documents/S4_IAGI/Projet Metier/SOC-Copilot/ML/Windows/trained_models/training_meta_data"
)

def main():
    args = _parse_args()

    log.info(f"Loading artifacts from: {ARTIFACTS_DIR}")
    artifacts = load_artifacts(ARTIFACTS_DIR)

    log.info(f"Loading input events from: {args.input}")
    df_raw = pd.read_csv(args.input, low_memory=False)
    log.info(f"  Loaded {len(df_raw):,} events × {df_raw.shape[1]} columns")

    if args.predict:
        tactic_names = predict(df_raw, artifacts)
        log.info("Predictions:")
        unique, counts = np.unique(tactic_names, return_counts=True)
        for tactic, count in zip(unique, counts):
            log.info(f"  {tactic:<35} {count:>6,} events")
    else:
        X_final = preprocess(df_raw, artifacts)
        log.info(f"Preprocessing complete. Output shape: {X_final.shape}")

        if args.output:
            out_path = Path(args.output)
            np.save(out_path, X_final)
            log.info(f"Saved to: {out_path}")


if __name__ == "__main__":
    main()