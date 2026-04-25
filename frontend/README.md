# SOC Copilot Streamlit Frontend

This frontend is fully isolated in the `frontend` folder and does not modify backend code.

## Features

- Multi-page Streamlit app aligned with FastAPI contracts in `agent/api.py`
- Alert Analyzer page for `POST /analyze`
- Alerts Inventory page for `GET /alerts`
- SOC Chat page for `POST /chat`
- Knowledge Base page for local runbooks + ATT&CK/ENGAGE/D3FEND mappings
- System Health page for runtime probes and smoke checks

## Folder Layout

```text
frontend/
  app.py
  requirements.txt
  .streamlit/config.toml
  core/
    config.py
    api_client.py
    state.py
    theme.py
    data_loaders.py
  components/
    ui.py
  pages/
    1_Alert_Analyzer.py
    2_Alerts_Inventory.py
    3_SOC_Chat.py
    4_Knowledge_Base.py
    5_System_Health.py
```

## Run Locally

1. Create and activate a Python virtual environment.
2. Install dependencies:

```bash
pip install -r frontend/requirements.txt
```

3. Set optional environment variables:

```bash
export SOC_API_BASE_URL="http://localhost:8000"
export SOC_API_TIMEOUT="45"
export SOC_DEFAULT_HOURS="24"
export SOC_MAX_TABLE_ROWS="1500"
```

4. Launch the app:

```bash
streamlit run frontend/app.py
```

## Notes

- The app expects the FastAPI backend to be available.
- When `/alerts` is unavailable, the UI keeps working and surfaces backend warning messages.
- The Knowledge Base page reads local files from `data/runbooks`, `data/engage`, and `data/d3fend`.
