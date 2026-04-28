# SOC Copilot - Setup & Run Guide

## Project Architecture

The SOC Copilot project consists of two main components:

- **Backend**: FastAPI agent (`agent/api.py`) that analyzes security alerts
- **Frontend**: Streamlit app (`frontend/app.py`) that provides the user interface

They communicate via HTTP at `http://localhost:8000` by default.

---

## Prerequisites

Ensure you have the following installed:
- Python 3.9+
- Git
- pip or conda

---

## Step 1: Backend Setup & Run

### 1.1 Install Backend Dependencies

From the project root:

```bash
# Create a virtual environment (recommended)
python -m venv backend_env

# Activate it
# On Windows:
backend_env\Scripts\activate
# On macOS/Linux:
source backend_env/bin/activate

# Identify and install backend requirements
# Scan agent/ for imports and install dependencies
pip install fastapi uvicorn langchain langchain-core langchain-ollama pydantic
pip install pandas requests neo4j chromadb

# Install additional dependencies as needed from your imports
pip install python-dotenv
```

### 1.2 Create/Configure `.env` File

The `.env` file already exists in the project root with configuration:

```
WAZUH_USERNAME=admin
WAZUH_PASSWORD=<PASSWORD>
WAZUH_HOST=100.97.198.85
WAZUH_PORT=55000

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<PASSWORD>

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<EMAIL>
SMTP_PASS=<PASSWORD>

SOC_EMAIL_TO=<EMAIL>
```

Ensure external services (Neo4j, Wazuh, etc.) are running before starting the backend.

### 1.3 Start the Backend Server

```bash
# From the project root, run FastAPI with uvicorn
uvicorn agent.api:app --host 0.0.0.0 --port 8000 --reload

# Output should show:
# INFO:     Uvicorn running on http://0.0.0.0:8000
# Visit http://localhost:8000/docs for interactive API documentation
```

**Keep this terminal running.**

---

## Step 2: Frontend Setup & Run

### 2.1 Install Frontend Dependencies

Open a **new terminal** and activate a separate venv:

```bash
# From the project root
python -m venv frontend_env

# Activate it
# On Windows:
frontend_env\Scripts\activate
# On macOS/Linux:
source frontend_env/bin/activate

# Install frontend dependencies
pip install -r frontend/requirements.txt
```

### 2.2 Configure Frontend (Optional)

Environment variables are loaded in `frontend/core/config.py`:

- `SOC_API_BASE_URL` - Backend API URL (default: `http://localhost:8000`)
- `SOC_API_TIMEOUT` - Request timeout in seconds (default: `45`)
- `SOC_DEFAULT_HOURS` - Default alert window (default: `24`)
- `SOC_MAX_TABLE_ROWS` - Max rows in tables (default: `1500`)

Set them before running:

```bash
# On Windows (PowerShell):
$env:SOC_API_BASE_URL="http://localhost:8000"

# On Windows (cmd):
set SOC_API_BASE_URL=http://localhost:8000

# On macOS/Linux:
export SOC_API_BASE_URL="http://localhost:8000"
```

### 2.3 Start the Frontend Server

```bash
# From the project root
streamlit run frontend/app.py

# Output should show:
# You can now view your Streamlit app in your browser.
# Local URL: http://localhost:8501
```

**Open your browser to http://localhost:8501**

---

## Step 3: Verify Connection

1. **Frontend Home Page**: Check the sidebar for "Backend Status"
   - Should show: `OK - SOC Copilot v1.0`
   - If "Offline": Backend is not running or unreachable

2. **Test Endpoints**:
   - Visit `http://localhost:8000/docs` for Swagger UI
   - Test `/health` endpoint
   - Try `/alerts` endpoint

3. **Explore Pages**:
   - **Alerts Inventory**: Loads alerts from Wazuh/OpenSearch
   - **Alert Analyzer**: Submit an alert for analysis
   - **SOC Chat**: Free-form queries to the agent
   - **Knowledge Base**: Local runbooks and threat mappings
   - **System Health**: Runtime diagnostics

---

## Project Structure Reference

```
soc-copilot/
├── agent/                 # FastAPI backend
│   ├── api.py            # Main endpoints
│   ├── graph.py          # LangGraph agent definition
│   ├── tools.py          # Tool definitions
│   ├── prompts.py        # System prompts
│   ├── knowledge_base.py # RAG integration
│   ├── graph_retriever.py
│   ├── neo4j_ingest/     # Neo4j ingestion
│   └── ...
├── frontend/             # Streamlit frontend
│   ├── app.py           # Main entry point
│   ├── requirements.txt
│   ├── core/            # Configuration & API client
│   ├── pages/           # Streamlit pages
│   └── components/      # UI components
├── data/                # Knowledge bases
│   ├── mitre_attack.json
│   ├── d3fend/
│   ├── engage/
│   ├── runbooks/
│   └── sigma_rules/
├── RAG/                 # Vector DB setup
├── ML/                  # ML models
├── input/               # Input data & clients
├── .env                 # Environment variables
└── main.ipynb          # Demo notebook
```

---

## Common Issues & Troubleshooting

### Backend fails to start
- **Error**: `ModuleNotFoundError: No module named 'agent'`
  - **Solution**: Run from project root; ensure Python path includes current directory
  
- **Error**: `Connection refused` to Neo4j/Wazuh
  - **Solution**: Check `.env` variables and verify external services are running

### Frontend shows "Offline"
- **Issue**: Backend unreachable
  - **Solution**: 
    1. Check backend is running on port 8000
    2. Verify `SOC_API_BASE_URL` environment variable
    3. Check firewall/network connectivity

### Frontend pages crash
- **Issue**: Missing dependencies or API errors
  - **Solution**: 
    1. Reinstall frontend requirements: `pip install -r frontend/requirements.txt --force-reinstall`
    2. Check browser console for errors
    3. Check backend terminal for stack traces

### Slow responses
- **Solution**: Backend processes are CPU-intensive
  - Ensure LLM (Ollama) and Neo4j are running
  - Monitor resource usage
  - Increase `SOC_API_TIMEOUT` if needed

---

## Development & Testing

### Run unit tests
```bash
pytest test/
```

### Run demo/integration tests
```bash
python test/run_demo.py
```

### Jupyter notebooks
```bash
jupyter notebook main.ipynb
```

### Run the Windows ML predictor

The portable helper lives in [agent/ml_predictor.py](agent/ml_predictor.py) and uses the checked-in artifact bundle at `ML/Windows/trained_models/training_meta_data` by default.

```bash
python -m agent.ml_predictor --input combined_3000.csv --output enriched_alerts.csv
```

If your artifacts live elsewhere, point the script at them with:

```bash
set SOC_ML_ARTIFACTS_DIR=C:\path\to\training_meta_data
```

On the Wazuh side, the usual pattern is to export the alert data to CSV/JSON, run this script, then send the enriched result to the agent API.

### Realtime end-to-end test (Wazuh -> ML -> Agent -> Report)

Use the realtime bridge script at `test/run_realtime_wazuh_pipeline.py`.

1. Start backend API:

```bash
uvicorn agent.api:app --host 0.0.0.0 --port 8000 --reload
```

2. In another terminal, run the realtime pipeline:

```bash
python test/run_realtime_wazuh_pipeline.py --api http://127.0.0.1:8000 --windows-only --minutes-window 2 --poll-seconds 5
```

3. Trigger an attack event on a monitored endpoint (for example SSH brute force, suspicious PowerShell, or port scan) so Wazuh emits an alert.

4. Pipeline behavior per new alert:
  - Pull full raw alert from OpenSearch (`wazuh-alerts-*`)
  - Call `POST /ml/predict`
  - Inject ML prediction into alert payload
  - Call `POST /analyze`
  - Save output JSON into `report/realtime/`

5. Check generated artifacts:
  - JSON bundle per alert in `report/realtime/`
  - PDF path in `analyze_response.report.pdf_path` (if PDF generation is enabled)
  - Email status in `analyze_response.report.email_status`

Useful flags:

```bash
# run one cycle only
python test/run_realtime_wazuh_pipeline.py --once

# custom ML artifact directory
python test/run_realtime_wazuh_pipeline.py --artifacts-dir C:\path\to\training_meta_data
```

---

## Production Deployment

For production:

1. **Backend**: Use Gunicorn or other ASGI server
   ```bash
   gunicorn agent.api:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
   ```

2. **Frontend**: Deploy as Streamlit Cloud or containerized
   ```bash
   streamlit run frontend/app.py --server.port=8501 --server.address=0.0.0.0
   ```

3. **Docker**: Create Dockerfile for reproducible deployments

---

## Quick Reference Commands

```bash
# Backend (Terminal 1)
backend_env\Scripts\activate          # Windows
source backend_env/bin/activate       # macOS/Linux
uvicorn agent.api:app --reload

# Frontend (Terminal 2)
frontend_env\Scripts\activate         # Windows
source frontend_env/bin/activate      # macOS/Linux
streamlit run frontend/app.py

# Browser
http://localhost:8501                 # Streamlit frontend
http://localhost:8000/docs            # FastAPI Swagger UI
```

---

## Support

For issues, check:
1. `.env` configuration
2. External service connectivity (Neo4j, Wazuh, Ollama)
3. Python version compatibility (3.9+)
4. Log output from both terminals
