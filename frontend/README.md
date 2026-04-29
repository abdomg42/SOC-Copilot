# SOC Copilot Frontend

Streamlit interface for the SOC Copilot backend. The app lives entirely in `frontend/` and communicates with the FastAPI service exposed by `agent/api.py`.

## What It Does

- SOC Dashboard for alert triage and trend visibility
- SOC Chat for free-form questions against the backend agent
- Clean fallback behavior when the backend is offline or returns warnings

## Requirements

- Python 3.9 or newer
- A running backend at `http://localhost:8000` or a custom API base URL

## Install

From the project root:

```bash
python -m venv frontend_env
source frontend_env/bin/activate
pip install -r frontend/requirements.txt
```

On Windows, activate the virtual environment with `frontend_env\Scripts\activate`.

## Run

Start the backend first, then launch the frontend:

```bash
streamlit run frontend/app.py
```

The app opens at `http://localhost:8501`.

## Configuration

These environment variables are read by `frontend/core/config.py`:

- `SOC_API_BASE_URL` - backend base URL, default `http://localhost:8000`
- `SOC_API_TIMEOUT` - request timeout in seconds, default `45`
- `SOC_DEFAULT_HOURS` - default alert lookback window, default `24`
- `SOC_MAX_TABLE_ROWS` - maximum rows shown in tables, default `1500`

Example:

```bash
export SOC_API_BASE_URL="http://localhost:8000"
export SOC_API_TIMEOUT="45"
export SOC_DEFAULT_HOURS="24"
export SOC_MAX_TABLE_ROWS="1500"
```

## Project Layout

```text
frontend/
  app.py
  requirements.txt
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

## Troubleshooting

- If the dashboard shows the backend as offline, verify the FastAPI server is running and `SOC_API_BASE_URL` is correct.
- If Streamlit fails to import packages, reinstall the frontend dependencies with `pip install -r frontend/requirements.txt`.
