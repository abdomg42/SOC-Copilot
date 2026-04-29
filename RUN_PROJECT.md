# SOC Copilot - Setup & Run Guide

## Overview

SOC Copilot combines three working areas:

- **Backend**: FastAPI agent in `agent/api.py`
- **Frontend**: Streamlit UI in `frontend/app.py`
- **ML and enrichment**: Windows and network inference helpers under `ML/` plus the reusable predictor in `agent/ml_predictor.py`

The backend and frontend communicate over HTTP at `http://localhost:8000` by default.

## Repository Layout

```text
SOC-Copilot/
├── agent/      FastAPI routes, LangGraph logic, Neo4j ingest, report generation
├── frontend/   Streamlit dashboard and chat UI
├── ML/         Network and Windows inference pipelines, notebooks, trained models
├── RAG/        Knowledge-base build utilities
├── input/      Wazuh/OpenSearch client helpers
├── data/       MITRE, D3FEND, ENGAGE, and Chroma assets
├── report/     Runtime and realtime outputs
└── RUN_PROJECT.md
```

## Prerequisites

Install these before running the project:

- Python 3.9+
- Git
- Access to the external services used by the project, typically:
  - Neo4j
  - Wazuh/OpenSearch
  - Ollama for the chat model
  - SMTP for email notifications if enabled

## Install

From the project root, create one environment and install the root dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate`.

If you want a smaller install, the repository also keeps component-level dependency files:

- `frontend/requirements.txt` for the UI only
- `ML/requirements.txt` for the ML notebooks and inference helpers

## Configure Environment

The project expects a `.env` file in the repository root. The main backend integrations use values like:

```bash
WAZUH_USERNAME=<USERNAME>
WAZUH_PASSWORD=<PASSWORD>
WAZUH_HOST=<HOST>
WAZUH_PORT=55000

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<PASSWORD>

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<EMAIL>
SMTP_PASS=<PASSWORD>

SOC_EMAIL_TO=<EMAIL>
SOC_ML_ARTIFACTS_DIR=<OPTIONAL_PATH>
```

The frontend also reads these optional settings from the environment:

- `SOC_API_BASE_URL` - backend URL, default `http://localhost:8000`
- `SOC_API_TIMEOUT` - request timeout in seconds, default `45`
- `SOC_DEFAULT_HOURS` - default alert lookback window, default `24`
- `SOC_MAX_TABLE_ROWS` - max table rows, default `1500`

## Run the Backend

Start the FastAPI server from the repository root:

```bash
uvicorn agent.api:app --host 0.0.0.0 --port 8000 --reload
```

Useful backend routes:

- `GET /health`
- `GET /alerts`
- `POST /chat`
- `POST /analyze`
- `POST /ml/predict`

API docs are available at `http://localhost:8000/docs`.

## Run the Frontend

With the backend running, start the UI in a second terminal:

```bash
streamlit run frontend/app.py
```

The app opens at `http://localhost:8501`.

## Use the ML Predictor

The reusable Windows predictor is exposed by `agent/ml_predictor.py`:

```bash
python -m agent.ml_predictor --input combined_3000.csv --output enriched_alerts.csv
```

To point at a custom model artifact directory, use `--artifacts` or set `SOC_ML_ARTIFACTS_DIR`:

```bash
python -m agent.ml_predictor --input combined_3000.csv --output enriched_alerts.csv --artifacts C:\path\to\training_meta_data
```

## Verify the Stack

1. Check the backend health endpoint: `http://localhost:8000/health`
2. Open the frontend at `http://localhost:8501`
3. Confirm the sidebar shows the backend as available
4. Try the chat page and the alert dashboard
5. Call `GET /alerts` in the browser or via the frontend to confirm Wazuh/OpenSearch connectivity

## Common Issues

- If `uvicorn` cannot import `agent`, make sure you are running the command from the repository root.
- If the backend returns OpenSearch or Wazuh errors, verify the `.env` values and the remote services.
- If the frontend shows the backend as offline, confirm `SOC_API_BASE_URL` and the backend port.
- If the ML predictor cannot load artifacts, set `SOC_ML_ARTIFACTS_DIR` to the correct `training_meta_data` directory.

## Helpful Files

- Backend API: [agent/api.py](agent/api.py)
- Frontend app: [frontend/app.py](frontend/app.py)
- ML predictor: [agent/ml_predictor.py](agent/ml_predictor.py)
- Frontend config: [frontend/core/config.py](frontend/core/config.py)
- Root dependencies: [requirements.txt](requirements.txt)
