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



warnings.filterwarnings("ignore")

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)




REQUIRED_RAW_COLUMNS: list[str] = [
    # Process / Image
    "_source.data.win.eventdata.image",
    "_source.data.win.eventdata.parentImage",
    # Command line
    "_source.data.win.eventdata.commandLine",
    # Logon / Authentication
    "_source.data.win.eventdata.logonType",
    # Integrity / Privilege
    "_source.data.win.eventdata.integrityLevel",
    "_source.data.win.eventdata.elevatedToken",
    # Event taxonomy
    "_source.data.win.system.eventID",
    # Network
    "_source.data.win.eventdata.destinationPort",
    "_source.data.win.eventdata.sourcePort",
    "_source.data.win.eventdata.destinationIp",
    # Rule severity
    "_source.rule.level",
    "_source.rule.firedtimes",
    # Temporal
    "_source.@timestamp",
    # Categorical
    "_source.data.win.system.channel",
    "_source.decoder.name",
    "_source.data.win.system.severityValue",
    "_source.agent.name",
    "_source.data.win.system.providerName",
]

# Columns that must NEVER be present at inference (label leakage).
LEAKAGE_PATTERNS: list[str] = [
    "rule.mitre", "rule.id", "rule.description", "rule.groups",
    "full_log",   "rule.pci",  "rule.hipaa",    "rule.tsc",
    "rule.nist",  "rule.gpg",  "rule.gdpr",     "rule.cis",
    "rule.frequency", "rule.mail", "rule.info",
    "_index", "_id", "_version", "_score",
    "sca.check.compliance", "rule.mitre_tactics",
    "rule.mitre_techniques", "rule.mitre_mitigations",
    "rule.soc", "rule.cis_csc", "sca.policy_id",
]



def audit_leakage(df: pd.DataFrame) -> list[str]:
    """Detect leakage columns in the DataFrame and return their names.
    
    Returns a list of column names that match leakage patterns.
    These columns should be dropped before inference.
    """
    def is_leakage(col: str) -> bool:
        return any(pattern in col for pattern in LEAKAGE_PATTERNS)

    found = [c for c in df.columns if is_leakage(c)]
    if found:
        log.warning(
            f"Leakage columns detected in input — dropping {len(found)} column(s):\n  {found}"
        )
    return found


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

