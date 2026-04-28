"""
preprocess_inference.py
=======================
Windows APT 2025 — Inference-Time Preprocessing Script
-------------------------------------------------------
Replicates EXACTLY the feature-engineering and preprocessing steps
performed during training (windows_apt_2025_pipeline_v2.ipynb).

Inference pipeline order (must match training):
    raw DataFrame
        → build_features()          (APT feature engineering)
        → preprocessor.transform()  (ColumnTransformer: impute + scale/encode)
        → var_filter.transform()    (VarianceThreshold)
        → model.predict()

Usage
-----
    from preprocess_inference import load_artifacts, preprocess

    artifacts = load_artifacts("path/to/artifacts/")
    X_ready   = preprocess(df_raw, artifacts)
    tactic_ids   = artifacts["model"].predict(X_ready)
    tactic_names = artifacts["label_encoder"].inverse_transform(tactic_ids)

Or run standalone to validate a CSV:
    python preprocess_inference.py --artifacts ./artifacts --input events.csv
"""


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

from .utilities import audit_leakage, audit_missing_columns, validate_feature_schema

warnings.filterwarnings("ignore")

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. RAW COLUMN REGISTRY
# ---------------------------------------------------------------------------
# Every raw Wazuh column that build_features() reads.
# At inference time your input DataFrame MUST contain these columns
# (missing ones are handled gracefully with df.get(), but you should
#  surface any absent columns as a warning).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 2. FEATURE ENGINEERING  (exact replica of Section 6 in the notebook)
# ---------------------------------------------------------------------------

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Engineer all APT-specific features from raw Wazuh columns.

    Parameters
    ----------
    df : pd.DataFrame
        Raw event DataFrame containing the Wazuh/SIEM columns listed in
        REQUIRED_RAW_COLUMNS. Missing columns are handled with pd.Series
        defaults (zeros / empty strings) matching training behaviour.

    Returns
    -------
    pd.DataFrame
        Feature matrix with columns named feat_* ready for the
        ColumnTransformer. Index is preserved from df.
    """
    out = pd.DataFrame(index=df.index)

    # ── Helpers ──────────────────────────────────────────────────────────────
    def safe_str(series: pd.Series) -> pd.Series:
        return series.astype("string").fillna("").str.strip().str.lower()

    def exe_from_path(series: pd.Series) -> pd.Series:
        s = safe_str(series).str.replace(r"\\\\", "\\", regex=False)
        result = s.str.split(r"[/\\]").str[-1]
        return result.replace("", "__missing__").fillna("__missing__")

    # ── 6.1  Process / Image features ────────────────────────────────────────
    exe     = exe_from_path(df.get("_source.data.win.eventdata.image",
                                   pd.Series(dtype=str, index=df.index)))
    par_exe = exe_from_path(df.get("_source.data.win.eventdata.parentImage",
                                   pd.Series(dtype=str, index=df.index)))

    LOLBINS = {
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
        "bitsadmin.exe", "curl.exe", "wget.exe", "msiexec.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe",
    }
    RECON_BINS = {
        "net.exe", "net1.exe", "whoami.exe", "ipconfig.exe",
        "nltest.exe", "arp.exe", "nslookup.exe", "tracert.exe",
        "systeminfo.exe", "quser.exe", "query.exe",
    }
    LATERAL_BINS = {
        "psexec.exe", "wmic.exe", "winrs.exe", "sc.exe",
        "at.exe", "schtasks.exe", "mstsc.exe",
    }
    SYSTEM_PROCS = {
        "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe",
        "wininit.exe", "services.exe", "explorer.exe",
    }

    out["feat_is_lolbin"]        = exe.isin(LOLBINS).astype("int8")
    out["feat_is_recon_bin"]     = exe.isin(RECON_BINS).astype("int8")
    out["feat_is_lateral_bin"]   = exe.isin(LATERAL_BINS).astype("int8")
    out["feat_is_system_proc"]   = exe.isin(SYSTEM_PROCS).astype("int8")
    out["feat_parent_is_office"] = par_exe.str.contains(
        r"word|excel|outlook|powerpnt|winword", regex=True, na=False
    ).astype("int8")
    out["feat_parent_is_shell"]  = par_exe.isin(
        {"cmd.exe", "powershell.exe", "wscript.exe"}
    ).astype("int8")
    out["feat_parent_is_lolbin"] = par_exe.isin(LOLBINS).astype("int8")
    # Unusual parent: system process spawning interactive shell
    out["feat_unusual_parent"]   = (
        par_exe.isin(SYSTEM_PROCS) & exe.isin(LOLBINS)
    ).astype("int8")

    # ── 6.2  Command-line heuristics ─────────────────────────────────────────
    cmd = safe_str(df.get("_source.data.win.eventdata.commandLine",
                          pd.Series(dtype=str, index=df.index)))

    out["feat_cmd_len"]          = cmd.str.len().clip(0, 2000).astype("int16")
    out["feat_cmd_has_encoded"]  = cmd.str.contains(
        r"-enc|-e |-encodedcommand|base64", regex=True, na=False
    ).astype("int8")
    out["feat_cmd_has_download"] = cmd.str.contains(
        r"iex|invoke-expression|downloadstring|downloadfile|wget|curl|bitsadmin",
        regex=True, na=False,
    ).astype("int8")
    out["feat_cmd_has_bypass"]   = cmd.str.contains(
        r"bypass|unrestricted|hidden|-w hidden|-windowstyle", regex=True, na=False
    ).astype("int8")
    out["feat_cmd_has_pipe"]     = cmd.str.contains(r"\|", regex=False).astype("int8")
    out["feat_cmd_has_redirect"] = cmd.str.contains(r">|>>", regex=False).astype("int8")
    out["feat_cmd_has_obfusc"]   = cmd.str.contains(
        r"\^|`|\$\(|%[a-z]%", regex=True, na=False
    ).astype("int8")
    out["feat_cmd_has_net_util"] = cmd.str.contains(
        r"net user|net group|net localgroup|net accounts", regex=True, na=False
    ).astype("int8")
    out["feat_cmd_has_whoami"]   = cmd.str.contains("whoami", regex=False).astype("int8")
    out["feat_cmd_has_schtask"]  = cmd.str.contains(
        r"schtasks|at \d", regex=True, na=False
    ).astype("int8")
    out["feat_cmd_has_reg"]      = cmd.str.contains(
        r"reg add|reg delete|reg query|regedit", regex=True, na=False
    ).astype("int8")
    out["feat_cmd_has_mimikatz"] = cmd.str.contains(
        r"sekurlsa|lsadump|mimikatz|kerberos::ptt|pass-the-hash", regex=True, na=False
    ).astype("int8")

    # ── 6.3  Logon / Authentication features ─────────────────────────────────
    logon_type = pd.to_numeric(
        df.get("_source.data.win.eventdata.logonType",
               pd.Series(dtype=str, index=df.index)),
        errors="coerce",
    ).fillna(-1).astype("int8")
    out["feat_logon_type"]       = logon_type
    out["feat_logon_network"]    = (logon_type == 3).astype("int8")   # Network logon
    out["feat_logon_remote_int"] = (logon_type == 10).astype("int8")  # RDP
    out["feat_logon_service"]    = (logon_type == 5).astype("int8")   # Service logon
    out["feat_logon_batch"]      = (logon_type == 4).astype("int8")   # Batch logon

    # ── 6.4  Integrity / Privilege features ──────────────────────────────────
    INTEGRITY_MAP = {"low": 0, "medium": 1, "high": 2, "system": 3, "": -1}
    il = safe_str(df.get("_source.data.win.eventdata.integrityLevel",
                         pd.Series(dtype=str, index=df.index)))
    out["feat_integrity_level"]  = il.map(INTEGRITY_MAP).fillna(-1).astype("int8")
    out["feat_high_integrity"]   = (out["feat_integrity_level"] >= 2).astype("int8")

    elev = safe_str(df.get("_source.data.win.eventdata.elevatedToken",
                           pd.Series(dtype=str, index=df.index)))
    out["feat_elevated_token"]   = (elev == "%%1842").astype("int8")

    # ── 6.5  Event taxonomy features ─────────────────────────────────────────
    eid = pd.to_numeric(
        df.get("_source.data.win.system.eventID",
               pd.Series(dtype=str, index=df.index)),
        errors="coerce",
    ).fillna(0)

    LOGON_EIDS   = {4624, 4625, 4648, 4768, 4769, 4776}
    PROC_EIDS    = {1, 4688}
    NET_EIDS     = {3, 5156, 5158}
    REG_EIDS     = {12, 13, 14}
    FILE_EIDS    = {11, 23}
    PRIV_EIDS    = {4673, 4674, 4672}
    AUDIT_EIDS   = {4719, 4907}
    LATERAL_EIDS = {7045, 4697}

    out["feat_eid_logon"]    = eid.isin(LOGON_EIDS).astype("int8")
    out["feat_eid_process"]  = eid.isin(PROC_EIDS).astype("int8")
    out["feat_eid_network"]  = eid.isin(NET_EIDS).astype("int8")
    out["feat_eid_registry"] = eid.isin(REG_EIDS).astype("int8")
    out["feat_eid_file"]     = eid.isin(FILE_EIDS).astype("int8")
    out["feat_eid_priv"]     = eid.isin(PRIV_EIDS).astype("int8")
    out["feat_eid_audit"]    = eid.isin(AUDIT_EIDS).astype("int8")
    out["feat_eid_lateral"]  = eid.isin(LATERAL_EIDS).astype("int8")
    out["feat_eid_raw"]      = eid.clip(0, 65535).astype("int32")

    # ── 6.6  Network features ─────────────────────────────────────────────────
    dport = pd.to_numeric(
        df.get("_source.data.win.eventdata.destinationPort",
               pd.Series(dtype=str, index=df.index)),
        errors="coerce",
    ).fillna(-1)
    # sourcePort is read but only used as an input reference in training
    # (stored via dport-derived features); kept here to mirror training
    _sport = pd.to_numeric(  # noqa: F841  (consumed upstream in training)
        df.get("_source.data.win.eventdata.sourcePort",
               pd.Series(dtype=str, index=df.index)),
        errors="coerce",
    ).fillna(-1)

    out["feat_dst_port"]           = dport.clip(-1, 65535).astype("int32")
    out["feat_dst_port_well_known"]= (dport.between(1, 1023)).astype("int8")
    out["feat_dst_port_http"]      = dport.isin([80, 443, 8080, 8443]).astype("int8")
    out["feat_dst_port_c2_common"] = dport.isin([4444, 4445, 1234, 6666, 8888, 31337]).astype("int8")
    out["feat_dst_port_smb"]       = dport.isin([445, 139]).astype("int8")
    out["feat_dst_port_rdp"]       = dport.isin([3389]).astype("int8")
    out["feat_dst_port_high"]      = (dport > 49151).astype("int8")

    dst_ip = safe_str(df.get("_source.data.win.eventdata.destinationIp",
                             pd.Series(dtype=str, index=df.index)))
    out["feat_dst_is_private"]  = dst_ip.str.match(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
    ).astype("int8")
    out["feat_dst_is_loopback"] = dst_ip.str.startswith("127.").astype("int8")

    # ── 6.7  Rule severity features ───────────────────────────────────────────
    rule_level = pd.to_numeric(
        df.get("_source.rule.level",
               pd.Series(dtype=str, index=df.index)),
        errors="coerce",
    ).fillna(0)
    out["feat_rule_level"]    = rule_level.clip(0, 15).astype("int8")
    out["feat_rule_high_sev"] = (rule_level >= 10).astype("int8")
    out["feat_rule_critical"] = (rule_level >= 13).astype("int8")

    fired = pd.to_numeric(
        df.get("_source.rule.firedtimes",
               pd.Series(dtype=str, index=df.index)),
        errors="coerce",
    ).fillna(1)
    out["feat_fired_times"] = np.log1p(fired).astype("float32")

    # ── 6.8  Temporal features ────────────────────────────────────────────────
    ts_col = "_source.@timestamp"
    if ts_col in df.columns:
        ts = pd.to_datetime(df[ts_col], errors="coerce", utc=True)
        out["feat_hour"]       = ts.dt.hour.fillna(-1).astype("int8")
        out["feat_dow"]        = ts.dt.dayofweek.fillna(-1).astype("int8")
        out["feat_is_night"]   = ((ts.dt.hour < 6) | (ts.dt.hour >= 22)).astype("int8")
        out["feat_is_weekend"] = (ts.dt.dayofweek >= 5).astype("int8")
    else:
        log.warning("Column '_source.@timestamp' not found — temporal features set to -1.")
        out[["feat_hour", "feat_dow", "feat_is_night", "feat_is_weekend"]] = -1

    # ── 6.9  Categorical features ─────────────────────────────────────────────
    out["feat_channel"]       = safe_str(df.get("_source.data.win.system.channel",
                                                pd.Series(dtype=str, index=df.index)))
    out["feat_decoder_name"]  = safe_str(df.get("_source.decoder.name",
                                                pd.Series(dtype=str, index=df.index)))
    out["feat_sev_value"]     = safe_str(df.get("_source.data.win.system.severityValue",
                                                pd.Series(dtype=str, index=df.index)))
    out["feat_agent_name"]    = safe_str(df.get("_source.agent.name",
                                                pd.Series(dtype=str, index=df.index)))
    out["feat_provider_name"] = safe_str(df.get("_source.data.win.system.providerName",
                                                pd.Series(dtype=str, index=df.index)))
    out["feat_integrity_cat"] = safe_str(df.get("_source.data.win.eventdata.integrityLevel",
                                                pd.Series(dtype=str, index=df.index)))

    return out


# ---------------------------------------------------------------------------
# 3. ARTIFACT LOADING
# ---------------------------------------------------------------------------

def load_artifacts(artifacts_dir: str | Path) -> dict:
    """
    Load the trained preprocessing objects and (optionally) the model.

    Expected files in artifacts_dir
    --------------------------------
    preprocessor.pkl        — fitted ColumnTransformer
    var_filter.pkl          — fitted VarianceThreshold
    label_encoder.pkl       — fitted LabelEncoder
    feature_metadata.json   — NUM_FEATS, CAT_FEATS, final_feature_names

    Optional
    --------
    inference_bundle.pkl    — single-file bundle (supersedes individual pkl files)
    model_lgbm.pkl          — or any model_*.pkl for end-to-end prediction

    Parameters
    ----------
    artifacts_dir : str | Path
        Directory produced by Section 13 of the training notebook.

    Returns
    -------
    dict with keys:
        preprocessor, var_filter, label_encoder,
        feature_metadata, model (may be None if not found)
    """
    artifacts_dir = Path(artifacts_dir)
    if not artifacts_dir.exists():
        raise FileNotFoundError(f"Artifacts directory not found: {artifacts_dir}")

    artifacts: dict = {}

    for key, fname in [
        ("preprocessor",  "preprocessor.pkl"),
        ("var_filter",    "var_filter.pkl"),
        ("label_encoder", "label_encoder.pkl"),
    ]:
        fpath = artifacts_dir / fname
        if not fpath.exists():
            raise FileNotFoundError(
                f"Required artifact not found: {fpath}\n"
                "Run Section 13 of the training notebook to generate it."
            )
        artifacts[key] = joblib.load(fpath)
        log.info(f"  ✓ {fname} loaded")

    # ── Feature metadata ──────────────────────────────────────────────────────
    meta_path = artifacts_dir / "feature_metadata.json"
    if meta_path.exists():
        with open(meta_path) as f:
            artifacts["feature_metadata"] = json.load(f)
        log.info(f"  ✓ feature_metadata.json loaded "
                 f"({artifacts['feature_metadata']['n_features_final']} final features)")
    else:
        log.warning("feature_metadata.json not found — schema validation skipped.")
        artifacts["feature_metadata"] = None

    # ── Optional: load model (any model_*.pkl) ────────────────────────────────
    model_file =  "/home/yassine/Documents/S4_IAGI/Projet Metier/SOC-Copilot/ML/Windows/trained_models/model_best_model.pkl"
    if model_file:
        artifacts["model"] = joblib.load(model_file)
        log.info(f"  ✓ Model loaded")
    else:
        artifacts["model"] = None
        log.warning("No model_*.pkl found — artifacts['model'] is None. "
                    "Load the model manually if needed.")

    return artifacts


# ---------------------------------------------------------------------------
# 5. MAIN PREPROCESSING FUNCTION
# ---------------------------------------------------------------------------

def preprocess(
    df_raw: pd.DataFrame,
    artifacts: dict,
    *,
    run_leakage_audit: bool = True,
    run_column_audit: bool = True,
) -> np.ndarray:
    """
    Full inference-time preprocessing pipeline.

    Parameters
    ----------
    df_raw : pd.DataFrame
        Raw Wazuh/SIEM event DataFrame. Each row is one event.
        Must contain the columns listed in REQUIRED_RAW_COLUMNS.
    artifacts : dict
        Output of load_artifacts().
    run_leakage_audit : bool
        If True (default), raise an error if leakage columns are present.
    run_column_audit : bool
        If True (default), log a warning for any missing raw columns.

    Returns
    -------
    np.ndarray, shape (n_events, n_features_final)
        Preprocessed feature matrix ready for model.predict().
    """
    if df_raw.empty:
        raise ValueError("Input DataFrame is empty.")

    log.info(f"Preprocessing {len(df_raw):,} events ...")

    # ── Step 0: Safety audits & data cleaning ──────────────────────────────────
    # Create a working copy to avoid modifying the original
    df_work = df_raw.copy()
    
    if run_leakage_audit:
        leakage_cols = audit_leakage(df_work)
        if leakage_cols:
            df_work = df_work.drop(columns=leakage_cols, errors="ignore")
            log.info(f"  ✓ Dropped {len(leakage_cols)} leakage column(s)")
    
    if run_column_audit:
        audit_missing_columns(df_work)

    # ── Step 1: Feature engineering ───────────────────────────────────────────
    log.info("Step 1/3 — Feature engineering (build_features) ...")
    X_feats = build_features(df_work)
    validate_feature_schema(X_feats, artifacts.get("feature_metadata"))

    # ── Step 2: ColumnTransformer (impute + scale/encode) ─────────────────────
    log.info("Step 2/3 — ColumnTransformer (impute + scale/ordinal encode) ...")
    preprocessor = artifacts["preprocessor"]
    X_transformed = preprocessor.transform(X_feats)

    # ── Step 3: VarianceThreshold filter ──────────────────────────────────────
    log.info("Step 3/3 — VarianceThreshold filter ...")
    var_filter = artifacts["var_filter"]
    X_final = var_filter.transform(X_transformed)

    log.info(f"  ✓ Output shape: {X_final.shape[0]:,} events × {X_final.shape[1]} features")
    return X_final


# ---------------------------------------------------------------------------
# 6. END-TO-END CONVENIENCE WRAPPER
# ---------------------------------------------------------------------------

def predict(
    df_raw: pd.DataFrame,
    artifacts: dict,
    *,
    return_proba: bool = False,
) -> np.ndarray:
    """
    End-to-end: raw DataFrame → MITRE tactic label strings.

    Parameters
    ----------
    df_raw : pd.DataFrame
        Raw Wazuh/SIEM events.
    artifacts : dict
        Output of load_artifacts().
    return_proba : bool
        If True, also return class probabilities (model must support predict_proba).

    Returns
    -------
    tactic_names : np.ndarray of str
        Predicted MITRE ATT&CK tactic for each event.
    proba : np.ndarray, shape (n_events, n_classes)  — only if return_proba=True
    """
    model = artifacts.get("model")
    if model is None:
        raise ValueError(
            "artifacts['model'] is None. Load the model first:\n"
            "  artifacts['model'] = joblib.load('path/to/model_lgbm.pkl')"
        )

    le = artifacts["label_encoder"]

    X_ready = preprocess(df_raw, artifacts)
    tactic_ids   = model.predict(X_ready)
    tactic_names = le.inverse_transform(tactic_ids)

    if return_proba:
        proba = model.predict_proba(X_ready)
        return tactic_names, proba

    return tactic_names


# ---------------------------------------------------------------------------
# 7. CLI ENTRY POINT
# ---------------------------------------------------------------------------

def _parse_args():
    import argparse
    parser = argparse.ArgumentParser(
        description="Windows APT 2025 — Inference Preprocessing CLI"
    ) 
    parser.add_argument(
        "--input", required=True,
        help="Path to a CSV file of raw Wazuh events to preprocess."
    )
    parser.add_argument(
        "--output", default=None,
        help="Optional path to save the preprocessed feature matrix as .npy."
    )
    parser.add_argument(
        "--predict", action="store_true",
        help="Run full prediction and print tactic labels (requires model_*.pkl)."
    )
    return parser.parse_args()

