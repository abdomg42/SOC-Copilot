from __future__ import annotations

from typing import Any, Dict, List

import streamlit as st

from core.api_client import SOCAPIClient
from core.config import load_config

CHAT_HISTORY_KEY = "chat_history"
LAST_ANALYSIS_KEY = "last_analysis"
DRAFT_ALERT_KEY = "draft_alert"


@st.cache_resource(show_spinner=False)
def get_api_client() -> SOCAPIClient:
    cfg = load_config()
    return SOCAPIClient(cfg.api_base_url, cfg.request_timeout_s)


def init_session_state() -> None:
    if CHAT_HISTORY_KEY not in st.session_state:
        st.session_state[CHAT_HISTORY_KEY] = []
    if LAST_ANALYSIS_KEY not in st.session_state:
        st.session_state[LAST_ANALYSIS_KEY] = None
    if DRAFT_ALERT_KEY not in st.session_state:
        st.session_state[DRAFT_ALERT_KEY] = {}


def get_chat_history() -> List[Dict[str, str]]:
    return st.session_state.get(CHAT_HISTORY_KEY, [])


def append_chat_message(role: str, content: str) -> None:
    history = st.session_state.setdefault(CHAT_HISTORY_KEY, [])
    history.append({"role": role, "content": content})


def clear_chat_history() -> None:
    st.session_state[CHAT_HISTORY_KEY] = []


def set_last_analysis(result: Dict[str, Any]) -> None:
    st.session_state[LAST_ANALYSIS_KEY] = result


def get_last_analysis() -> Dict[str, Any] | None:
    return st.session_state.get(LAST_ANALYSIS_KEY)
