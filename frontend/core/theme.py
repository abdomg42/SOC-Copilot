from __future__ import annotations

import streamlit as st


def apply_theme() -> None:
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;600;700&family=Fira+Code:wght@400;500&display=swap');

:root {
  --soc-bg: radial-gradient(circle at 12% 8%, #fff8e7 0%, #f1e8d6 34%, #eee4d1 60%, #e7ddc6 100%);
  --soc-panel: rgba(255, 255, 255, 0.76);
  --soc-border: rgba(73, 51, 34, 0.16);
  --soc-ink: #201b16;
  --soc-muted: #5f5348;
  --soc-accent: #b33121;
  --soc-accent-2: #d77b2d;
  --soc-ok: #1e7c49;
  --soc-warn: #ac6d00;
  --soc-danger: #a10f1e;
}

html, body, [class*="css"] {
  font-family: "Sora", "Trebuchet MS", "Segoe UI", sans-serif !important;
  color: var(--soc-ink);
}

.stApp {
  background: var(--soc-bg);
}

.block-container {
  max-width: 1300px;
  padding-top: 1.2rem;
  padding-bottom: 2.2rem;
}

.soc-hero {
  border: 1px solid var(--soc-border);
  border-radius: 18px;
  padding: 1.2rem 1.3rem;
  background: linear-gradient(160deg, rgba(255,255,255,0.8), rgba(244,233,212,0.7));
  backdrop-filter: blur(4px);
  box-shadow: 0 12px 26px rgba(0, 0, 0, 0.08);
  margin-bottom: 1.1rem;
}

.soc-title {
  font-size: clamp(1.45rem, 1.2rem + 1.2vw, 2.25rem);
  line-height: 1.12;
  letter-spacing: -0.01em;
  margin: 0;
}

.soc-subtitle {
  margin-top: 0.38rem;
  color: var(--soc-muted);
  font-size: 0.95rem;
}

.soc-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 0.72rem;
}

.soc-card {
  border: 1px solid var(--soc-border);
  border-radius: 14px;
  padding: 0.82rem 0.9rem;
  background: var(--soc-panel);
  box-shadow: 0 8px 20px rgba(0, 0, 0, 0.05);
}

.soc-card-label {
  color: var(--soc-muted);
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.soc-card-value {
  font-size: 1.15rem;
  font-weight: 600;
  margin-top: 0.25rem;
}

.soc-feed {
  display: grid;
  gap: 0.65rem;
}

.soc-feed-item {
  border: 1px solid var(--soc-border);
  border-radius: 12px;
  padding: 0.6rem 0.75rem;
  background: var(--soc-panel);
  display: grid;
  grid-template-columns: 140px 96px 1fr;
  gap: 0.6rem;
  align-items: center;
}

.soc-feed-title {
  font-weight: 600;
  line-height: 1.3;
}

.soc-feed-meta {
  color: var(--soc-muted);
  font-size: 0.78rem;
}

.soc-severity {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  border-radius: 999px;
  padding: 0.2rem 0.58rem;
  font-size: 0.74rem;
  font-weight: 600;
  border: 1px solid transparent;
}

.soc-severity-critical { background: rgba(161, 15, 30, 0.14); color: #7f0915; border-color: rgba(161, 15, 30, 0.3); }
.soc-severity-high { background: rgba(179, 49, 33, 0.13); color: #8b2419; border-color: rgba(179, 49, 33, 0.26); }
.soc-severity-medium { background: rgba(215, 123, 45, 0.16); color: #885017; border-color: rgba(172, 109, 0, 0.24); }
.soc-severity-low { background: rgba(30, 124, 73, 0.16); color: #155e37; border-color: rgba(30, 124, 73, 0.26); }
.soc-severity-na { background: rgba(66, 63, 58, 0.12); color: #443f3a; border-color: rgba(66, 63, 58, 0.2); }

.soc-code {
  font-family: "Fira Code", "Consolas", monospace;
  font-size: 0.82rem;
}

[data-testid="stSidebar"] {
  background: linear-gradient(180deg, rgba(35, 29, 24, 0.98), rgba(43, 36, 30, 0.98));
  border-right: 1px solid rgba(255, 255, 255, 0.08);
}

[data-testid="stSidebar"] * {
  color: #efe6d8 !important;
}

button[kind="primary"] {
  border-radius: 12px !important;
  border: 1px solid rgba(0, 0, 0, 0.08) !important;
  background: linear-gradient(130deg, #ab2f20, #c35a25) !important;
}

button[kind="primary"]:hover {
  filter: brightness(1.05);
}

@media (max-width: 880px) {
  .block-container {
    padding-top: 0.9rem;
    padding-left: 0.8rem;
    padding-right: 0.8rem;
  }

  .soc-hero {
    border-radius: 14px;
    padding: 0.9rem;
  }

  .soc-feed-item {
    grid-template-columns: 1fr;
  }
}
</style>
        """,
        unsafe_allow_html=True,
    )
