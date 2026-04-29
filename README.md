# SOC Copilot

SOC Copilot is a security operations assistant that combines a FastAPI agent backend, a Streamlit frontend, knowledge-base ingestion, and ML helpers for alert enrichment and inference.

## Repository Layout

```text
SOC-Copilot/
  agent/        FastAPI backend, LangGraph agent, Neo4j ingest, report generation
  frontend/     Streamlit UI for alert triage and chat
  ML/           Network and Windows ML pipelines, notebooks, trained models
  RAG/          Knowledge base build utilities
  input/        Alert input helpers and Wazuh client
  data/         MITRE, D3FEND, ENGAGE, and Chroma assets
  report/       Generated runtime reports
  RUN_PROJECT.md
```

## What It Does

- Exposes a FastAPI backend in `agent/api.py`
- Serves a Streamlit dashboard in `frontend/app.py`
- Retrieves alerts, enriches them with graph and knowledge-base data, and produces SOC reports
- Provides ML inference helpers for network and Windows alert workflows

## Prerequisites

- Python 3.9 or newer
- Access to the external services configured in `.env`, such as Neo4j, Wazuh, SMTP, and Ollama if you use the agent workflows

## Install

From the project root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the virtual environment with `.venv\Scripts\activate`.

If you prefer to install only a subset, the repository also keeps dedicated dependency files in `frontend/requirements.txt` and `ML/requirements.txt`.

## Run the Backend

Start the FastAPI server from the project root:

```bash
uvicorn agent.api:app --host 0.0.0.0 --port 8000 --reload
```

The API documentation is available at `http://localhost:8000/docs`.

## Run the Frontend

With the backend running, start the Streamlit app:

```bash
streamlit run frontend/app.py
```

The UI opens at `http://localhost:8501`.

## ML Utilities

- Network inference helpers live under `ML/Network/`
- Windows inference helpers live under `ML/Windows/`
- Notebook examples are stored in the corresponding `notebook/` directories

## Configuration

The project uses environment variables from `.env` for backend integrations and the following frontend variables:

- `SOC_API_BASE_URL` - backend base URL, default `http://localhost:8000`
- `SOC_API_TIMEOUT` - request timeout in seconds, default `45`
- `SOC_DEFAULT_HOURS` - default alert lookback window, default `24`
- `SOC_MAX_TABLE_ROWS` - maximum rows shown in tables, default `1500`

## Helpful References

- Setup and run guide: [RUN_PROJECT.md](RUN_PROJECT.md)
- Frontend-specific docs: [frontend/README.md](frontend/README.md)
- ML dependencies: [ML/requirements.txt](ML/requirements.txt)
- Frontend dependencies: [frontend/requirements.txt](frontend/requirements.txt)

## Common Entry Points

- Backend API: `agent/api.py`
- Frontend app: `frontend/app.py`
- ML Windows helper: `agent/ml_predictor.py`
- Report generation: `agent/report_generator.py`
