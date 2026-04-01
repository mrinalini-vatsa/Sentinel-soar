# SentinelSOAR

**SentinelSOAR** is an **AI-powered SOAR (Security Orchestration, Automation, and Response)**-style API for **IP threat analysis**. It enriches addresses with **AbuseIPDB** reputation data, applies a transparent rule engine, and returns a structured decision with simulated response actions—ready to run locally, in **Docker**, or on **Render** / **Railway**.

## Features

- **POST `/analyze`** — IP validation, external intel, enrichment, decision, and action (`blocked` / `monitored` / `allowed`)
- **Tri-state policy** — `> 70` malicious, `40–70` suspicious, `< 40` safe
- **Fail-open intel** — Timeouts and API errors yield score `0` and a safe outcome; degradation is recorded in logs
- **Structured JSON logs** — One audit line per request: `timestamp`, `ip`, `country`, `isp`, `threat_score`, `status`, `action` (plus optional `intel_degraded` / `intel_detail`)
- **Health & root** — `GET /health`, `GET /` for uptime and smoke checks
- **Deployment-ready** — `PORT` env support, slim Docker image, non-root friendly layout

## Tech stack

| Layer        | Choice                                      |
|-------------|---------------------------------------------|
| API         | FastAPI                                     |
| Server      | Uvicorn                                     |
| HTTP client | `requests` (sync, run in thread pool)       |
| Config      | `pydantic-settings` + `.env` (`python-dotenv`) |
| Validation  | Pydantic v2                                 |
| Optional UI | Streamlit                                   |

## Project structure

```
sentinel-soar/
├── app/
│   ├── main.py              # FastAPI app, lifespan, validation error handler
│   ├── core/
│   │   └── config.py        # Settings (ABUSEIPDB_API_KEY, timeouts, log path)
│   ├── routes/
│   │   ├── root.py          # GET /
│   │   ├── health.py        # GET /health
│   │   └── analyze.py       # POST /analyze
│   ├── services/
│   │   ├── abuseipdb.py     # AbuseIPDB client (timeouts, errors)
│   │   ├── enrichment.py
│   │   ├── decision_engine.py
│   │   ├── actions.py
│   │   └── pipeline.py
│   ├── models/
│   │   └── schemas.py
│   └── utils/
│       └── logger.py        # JSON-lines audit logging
├── main.py                  # CLI / dev server (honors PORT)
├── streamlit_app.py         # Optional dashboard
├── requirements.txt
├── Dockerfile
├── .dockerignore
└── README.md
```

## Setup (local)

```bash
cd sentinel-soar
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — set ABUSEIPDB_API_KEY (free tier: https://www.abuseipdb.com/)
```

Run the API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
# or (uses PORT from environment if set)
python main.py
```

Optional CLI:

```bash
python main.py --ip 8.8.8.8
```

Optional Streamlit:

```bash
streamlit run streamlit_app.py
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (**preferred**) |
| `API_KEY` | Legacy alias for the same key |
| `PORT` | Listen port (default `8000`; used by `main.py` and Docker) |
| `ABUSEIPDB_TIMEOUT_SECONDS` | Request timeout (default `15`) |
| `LOG_FILE` | JSON-lines log path (default `logs.jsonl`) |

## Docker

```bash
docker build -t sentinel-soar .
docker run --rm -e ABUSEIPDB_API_KEY=your_key -e PORT=8000 -p 8000:8000 sentinel-soar
```

Platforms like **Render** and **Railway** set `PORT` automatically; the container command expands `${PORT:-8000}`.

## API usage

### `GET /`

```json
{ "message": "SentinelSOAR API is running" }
```

### `GET /health`

```json
{ "status": "ok" }
```

### `POST /analyze`

**Request**

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'
```

**Response (example)**

```json
{
  "ip": "8.8.8.8",
  "country": "US",
  "isp": "Google LLC",
  "threat_score": 0,
  "status": "safe",
  "action": "allowed"
}
```

**Decision rules**

| Threat score | Status | Action |
|--------------|--------|--------|
| > 70 | `malicious` | `blocked` |
| 40 – 70 | `suspicious` | `monitored` |
| < 40 | `safe` | `allowed` |

**Errors**

- **422** — Invalid IP or body (see `message` / `errors` in the JSON body)
- **500** — Unexpected server error during analysis (rare)

If AbuseIPDB is down, times out, or the key is missing, the API still returns **200** with `threat_score: 0`, `status: "safe"`, `action: "allowed"`; check **`logs.jsonl`** for `intel_degraded` and `intel_detail`.

## Logging

Each successful `/analyze` emits one JSON line including:

`timestamp`, `event`, `ip`, `country`, `isp`, `threat_score`, `status`, `action`

Intel issues also emit `event: intel_degraded` with `intel_detail`.

## Future improvements

- Multi-provider intel fusion (VirusTotal, GreyNoise) and weighted scoring
- Authenticated API keys, rate limits, and Redis-backed quotas
- Real playbooks: ticketing, firewall, and EDR integrations
- Persistence and case management (Postgres + optional queue workers)

## License

Use for learning and internal tooling; ensure compliance with AbuseIPDB and your own security policies.
