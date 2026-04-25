from __future__ import annotations

import pandas as pd
import streamlit as st

from components.ui import render_hero, render_stat_cards
from core.config import (
    D3FEND_FULL_MAPPING_FILE,
    D3FEND_TACTICS_FILE,
    ENGAGE_MAPPING_FILE,
    RUNBOOK_DIR,
    load_config,
)
from core.data_loaders import (
    load_d3fend_full_mapping,
    load_d3fend_tactics,
    load_engage_mapping,
    load_runbooks,
)
from core.state import init_session_state
from core.theme import apply_theme

apply_theme()
init_session_state()
cfg = load_config()

render_hero(
    "Knowledge Base",
    "Explore local runbooks and MITRE/D3FEND/ENGAGE mappings bundled in this workspace.",
)

runbooks = load_runbooks(str(RUNBOOK_DIR))
engage_frame = load_engage_mapping(str(ENGAGE_MAPPING_FILE), max_rows=max(2000, cfg.max_table_rows * 2))
d3fend_full = load_d3fend_full_mapping(str(D3FEND_FULL_MAPPING_FILE), max_rows=max(2000, cfg.max_table_rows * 2))
d3fend_tactics = load_d3fend_tactics(str(D3FEND_TACTICS_FILE))

render_stat_cards(
    [
        ("Runbooks", str(len(runbooks))),
        ("ENGAGE Rows", str(len(engage_frame))),
        ("D3FEND Mapping Rows", str(len(d3fend_full))),
        ("D3FEND Taxonomy Rows", str(len(d3fend_tactics))),
    ]
)

tab1, tab2, tab3 = st.tabs(["Runbooks", "MITRE -> ENGAGE", "ATT&CK <-> D3FEND"])

with tab1:
    st.markdown("### Operational Runbooks")
    if not runbooks:
        st.warning("No runbook files found in data/runbooks.")
    else:
        names = list(runbooks.keys())
        selected = st.selectbox("Runbook", names)
        item = runbooks[selected]

        info_col1, info_col2 = st.columns([2, 1])
        with info_col1:
            st.caption(f"Source: {item['path']}")
        with info_col2:
            st.caption(f"MITRE tags: {item['mitre_ids']}")

        st.markdown(item["content"])

with tab2:
    st.markdown("### ATT&CK to ENGAGE Mapping")
    if engage_frame.empty:
        st.warning("ENGAGE mapping file is missing or empty.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            attack_filter = st.text_input("Filter by ATT&CK ID or technique", value="").strip().lower()
        with col2:
            eac_values = ["All"] + sorted(v for v in engage_frame["eac"].dropna().astype(str).unique())
            selected_eac = st.selectbox("ENGAGE Action", options=eac_values)

        view = engage_frame.copy()
        if attack_filter:
            view = view[
                view["attack_id"].astype(str).str.lower().str.contains(attack_filter, na=False)
                | view["attack_technique"].astype(str).str.lower().str.contains(attack_filter, na=False)
            ]
        if selected_eac != "All":
            view = view[view["eac"].astype(str) == selected_eac]

        st.dataframe(view.head(cfg.max_table_rows), use_container_width=True, hide_index=True, height=420)
        st.caption(f"Displaying {min(len(view), cfg.max_table_rows)} of {len(view)} filtered rows.")

        st.download_button(
            label="Download filtered ENGAGE CSV",
            data=view.to_csv(index=False),
            file_name="engage_filtered.csv",
            mime="text/csv",
        )

with tab3:
    st.markdown("### ATT&CK and D3FEND Correlation")
    if d3fend_full.empty:
        st.warning("D3FEND full mapping file is missing or empty.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            mitre_filter = st.text_input("Filter by ATT&CK technique ID (ex: T1078)", value="").strip().lower()
        with col2:
            tactic_values = ["All"] + sorted(
                v for v in d3fend_full["def_tactic_label"].dropna().astype(str).unique()
            )
            selected_tactic = st.selectbox("D3FEND Tactic", options=tactic_values)

        map_view = d3fend_full.copy()
        if mitre_filter:
            map_view = map_view[
                map_view["off_tech_id"].astype(str).str.lower().str.contains(mitre_filter, na=False)
                | map_view["off_tech_label"].astype(str).str.lower().str.contains(mitre_filter, na=False)
            ]
        if selected_tactic != "All":
            map_view = map_view[map_view["def_tactic_label"].astype(str) == selected_tactic]

        st.dataframe(map_view.head(cfg.max_table_rows), use_container_width=True, hide_index=True, height=380)
        st.caption(f"Displaying {min(len(map_view), cfg.max_table_rows)} of {len(map_view)} filtered rows.")

    st.markdown("### D3FEND Taxonomy Preview")
    if d3fend_tactics.empty:
        st.info("D3FEND taxonomy file not available.")
    else:
        tech_query = st.text_input("Search tactic or technique", value="").strip().lower()
        tax_view = d3fend_tactics.copy()
        if tech_query:
            mask = pd.Series(False, index=tax_view.index)
            for col in tax_view.columns:
                mask = mask | tax_view[col].astype(str).str.lower().str.contains(tech_query, na=False)
            tax_view = tax_view[mask]

        st.dataframe(tax_view.head(250), use_container_width=True, hide_index=True, height=300)
