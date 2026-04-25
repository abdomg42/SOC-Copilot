from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

import pandas as pd
import streamlit as st

MITRE_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


@st.cache_data(show_spinner=False)
def load_runbooks(runbook_dir: str) -> Dict[str, Dict[str, str]]:
    base = Path(runbook_dir)
    runbooks: Dict[str, Dict[str, str]] = {}
    if not base.exists():
        return runbooks

    for file_path in sorted(base.glob("*.md")):
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        title = file_path.stem.replace("_", " ").title()
        mitre_ids = sorted(set(MITRE_ID_PATTERN.findall(content)))
        runbooks[title] = {
            "path": str(file_path),
            "content": content,
            "mitre_ids": ", ".join(mitre_ids) if mitre_ids else "N/A",
        }
    return runbooks


@st.cache_data(show_spinner=False)
def load_engage_mapping(path: str, max_rows: int = 5000) -> pd.DataFrame:
    file_path = Path(path)
    if not file_path.exists():
        return pd.DataFrame()

    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        return pd.DataFrame()

    frame = pd.DataFrame(data)
    if max_rows > 0:
        frame = frame.head(max_rows)

    keep = [
        "attack_id",
        "attack_technique",
        "eac_id",
        "eac",
        "eav_id",
        "eav",
    ]
    cols = [c for c in keep if c in frame.columns]
    return frame[cols] if cols else frame


@st.cache_data(show_spinner=False)
def load_d3fend_full_mapping(path: str, max_rows: int = 5000) -> pd.DataFrame:
    file_path = Path(path)
    if not file_path.exists():
        return pd.DataFrame()

    frame = pd.read_csv(file_path)
    if max_rows > 0:
        frame = frame.head(max_rows)

    columns = [
        "def_tactic_label",
        "query_def_tech_label",
        "off_tech_id",
        "off_tech_label",
        "off_tactic_label",
        "def_artifact_label",
        "off_artifact_label",
    ]
    available = [c for c in columns if c in frame.columns]
    return frame[available] if available else frame


@st.cache_data(show_spinner=False)
def load_d3fend_tactics(path: str, max_rows: int = 800) -> pd.DataFrame:
    file_path = Path(path)
    if not file_path.exists():
        return pd.DataFrame()

    frame = pd.read_csv(file_path)
    if max_rows > 0:
        frame = frame.head(max_rows)

    columns = [
        "ID",
        "D3FEND Tactic",
        "D3FEND Technique",
        "D3FEND Technique Level 0",
        "D3FEND Technique Level 1",
        "Definition",
    ]
    available = [c for c in columns if c in frame.columns]
    return frame[available] if available else frame


def quick_rule_tags(text: str) -> List[str]:
    found = MITRE_ID_PATTERN.findall(text)
    return sorted(set(found))
