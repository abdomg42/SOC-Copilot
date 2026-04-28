# SOC Copilot Streamlit Frontend

This frontend is fully isolated in the `frontend` folder and does not modify backend code.

## Features

- Streamlined two-page Streamlit app aligned with FastAPI contracts in `agent/api.py`
- SOC Dashboard page for `GET /alerts` (summary cards, alert feed, trend charts)
- SOC Chat page for `POST /chat`

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
  components/
    ui.py
  pages/
    3_SOC_Chat.py
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
