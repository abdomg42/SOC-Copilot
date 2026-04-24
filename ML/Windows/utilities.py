# ---------------------------------------------------------------------------
# 4. VALIDATION UTILITIES
# ---------------------------------------------------------------------------


from __future__ import annotations

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


from preprocess_inference import LEAKAGE_PATTERNS , REQUIRED_RAW_COLUMNS

warnings.filterwarnings("ignore")

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)





def audit_leakage(df: pd.DataFrame) -> None:
    """Raise a ValueError if any leakage column is present in the DataFrame."""
    def is_leakage(col: str) -> bool:
        return any(pattern in col for pattern in LEAKAGE_PATTERNS)

    found = [c for c in df.columns if is_leakage(c)]
    if found:
        raise ValueError(
            f"Leakage columns detected in inference input — these must NEVER "
            f"be passed to the model:\n  {found}"
        )


def audit_missing_columns(df: pd.DataFrame) -> list[str]:
    """Return a list of required raw columns absent from df (non-fatal warning)."""
    missing = [c for c in REQUIRED_RAW_COLUMNS if c not in df.columns]
    if missing:
        log.warning(
            f"{len(missing)} required column(s) missing from input — "
            f"affected features will default to zero/empty:\n  {missing}"
        )
    return missing


def validate_feature_schema(
    X_feats: pd.DataFrame,
    feature_metadata: Optional[dict],
) -> None:
    """
    Cross-check the engineered feature column list against what was saved
    during training (feature_metadata.json).
    """
    if feature_metadata is None:
        log.warning("No feature_metadata.json available — schema validation skipped.")
        return

    expected_num = set(feature_metadata.get("numeric_features", []))
    expected_cat = set(feature_metadata.get("categorical_features", []))
    expected_all = expected_num | expected_cat
    actual_all   = set(X_feats.columns)

    missing_feats = expected_all - actual_all
    extra_feats   = actual_all - expected_all

    if missing_feats:
        log.warning(f"Features expected by preprocessor but not produced: {sorted(missing_feats)}")
    if extra_feats:
        log.warning(f"Extra features produced (will be dropped by ColumnTransformer): {sorted(extra_feats)}")
    if not missing_feats and not extra_feats:
        log.info("  ✓ Feature schema matches training exactly.")

