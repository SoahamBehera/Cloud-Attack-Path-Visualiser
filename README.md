# 🛡️ Cloud Attack Path Visualiser

**A Graph-Based Framework for Cloud Attack Path Discovery, Risk Assessment, and Visualization**

> ⚠️ **DEFENSIVE TOOL ONLY** — This tool analyzes *simulated* AWS-style JSON configs.
> It never contacts real cloud accounts or performs any attacks.

---

## Features

- **9 Deterministic Security Detectors** — SSH exposure, public DB ports, public S3, unencrypted storage, public RDS, overly permissive IAM, hardcoded secrets, and more
- **Graph-Based Attack Path Discovery** — Builds a networkx graph and finds multi-step attack paths from internet to high-value targets
- **Risk Scoring** — 0–100 overall risk score with severity breakdown
- **Interactive Visualization** — Pyvis-powered interactive network graph in the Streamlit dashboard
- **REST API** — FastAPI endpoints for programmatic access
- **Optional AI Explanation** — Uses OpenAI (if configured) to explain findings in plain English

## Architecture

```
src/            ← Core engine (no Streamlit dependency)
  models.py     ← Pydantic data models
  parser.py     ← JSON config parser
  detectors.py  ← Security misconfiguration detectors
  graph_builder.py ← Networkx graph construction
  pathfinder.py ← Attack path discovery
  risk_scorer.py ← Risk scoring
  explainer.py  ← AI explanation (optional)
  engine.py     ← Pipeline orchestrator

api/main.py     ← FastAPI REST API
app/streamlit_app.py ← Streamlit dashboard
tests/          ← pytest test suite
data/           ← Sample simulated configs
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run full test suite (73 tests)
pytest tests/ -v

# Launch the interactive Streamlit dashboard
streamlit run app.py

# Or start the FastAPI server
uvicorn api.main:app --reload
```

## API Usage

```bash
# Health check
curl http://localhost:8000/health

# Full analysis
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @data/sample_config.json \
  --data-urlencode "config@data/sample_config.json"

# Or with Python
import httpx, json
config = json.load(open("data/sample_config.json"))
resp = httpx.post("http://localhost:8000/analyze", json={"config": config})
print(resp.json())
```

## AI Explanation (Optional)

Set the `OPENAI_API_KEY` environment variable or add it to `.env`:

```bash
export OPENAI_API_KEY=sk-...
```

The AI is **only** used to explain results — all detection and path-finding is deterministic.

## License

MIT
