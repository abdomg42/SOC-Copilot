from __future__ import annotations

import streamlit as st

from components.ui import render_hero
from core.api_client import APIError
from core.state import (
    append_chat_message,
    clear_chat_history,
    get_api_client,
    get_chat_history,
    init_session_state,
)
from core.theme import apply_theme

apply_theme()
init_session_state()
client = get_api_client()

render_hero(
    "SOC Chat",
    "Ask free-form investigation questions to /chat while keeping a short conversation memory.",
)

controls_col1, controls_col2 = st.columns([1, 4])
with controls_col1:
    if st.button("Clear Chat", use_container_width=True):
        clear_chat_history()
        st.rerun()
with controls_col2:
    st.caption("The backend keeps the last 6 user turns when generating answers.")

history = get_chat_history()
for msg in history:
    role = msg.get("role", "assistant")
    content = msg.get("content", "")
    with st.chat_message("user" if role == "user" else "assistant"):
        st.markdown(content)

question = st.chat_input("Ask about alert context, attack sequence, or containment actions")
if question:
    history_snapshot = [dict(msg) for msg in history]
    append_chat_message("user", question)
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        with st.spinner("Building response...."):
            try:
                response = client.chat(question=question, history=history_snapshot)
                answer = response.get("answer", "No answer returned by backend.")
            except APIError as exc:
                answer = f"Backend error: {exc}"
        st.markdown(answer)

    append_chat_message("assistant", answer)
