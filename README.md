# API Abuse Detection & Request Behavior Analytics Platform (Prototype)

A working prototype that watches API request logs in real time, scores every client's
behaviour, raises alerts and automatically throttles or blocks abusive clients.

**Requirements:** Python 3.8+ only. No pip install, no internet needed.

## Run it
    cd api-abuse-detector
    python run.py            (Windows: py run.py)

Open http://127.0.0.1:8000. Normal traffic from 8 users starts automatically.
Click the buttons in "Attack simulator" to launch attacks and watch risk scores,
alerts and blocks appear live. `python run.py --fresh` starts with an empty database.

Run the tests: `python -m unittest discover -s tests`

## What it detects
| Rule | Signal | Weight |
|---|---|---|
| RATE_BURST | 60+ requests in 10s from one client | 35 |
| RATE_ANOMALY | Volume far above peers (median/MAD modified z-score >= 3.5) | 25 |
| CREDENTIAL_STUFFING | 10+ failed 401/403 on auth endpoints in 60s | 55 |
| ENDPOINT_ENUMERATION | 20+ distinct endpoints, 40%+ returning 404 | 40 |
| ID_SCANNING | 15+ sequential object IDs read (/users/1, /users/2 ...) | 40 |
| BOT_TIMING | Machine-regular request spacing (CV < 0.12) | 25 |
| KEY_SHARING | One API key used from 4+ IPs in 60s | 40 |
| SUSPICIOUS_UA | Empty or tool user-agent (sqlmap, curl, python-requests ...) | 10 |
| HIGH_ERROR_RATE | 60%+ of requests failing | 20 |

Weights add up to a risk score (0-100): <40 allow, 40-79 throttle, >=80 auto-block for
5 minutes. All thresholds are in DEFAULT_CONFIG at the top of app/detector.py.

## Connect your own API
    POST http://127.0.0.1:8000/api/ingest
    {"client":"api-key-or-user-id","ip":"1.2.3.4","method":"GET","path":"/api/users/42",
     "status":200,"user_agent":"...","latency_ms":35}
    -> {"action":"allow|throttle|block","score":12,"rules":[]}

See sample_client.py for an example to call from Flask/FastAPI/Express middleware.

## REST endpoints
GET /api/stats, GET /api/clients, GET /api/alerts?limit=N, POST /api/ingest,
POST /api/block {client}, POST /api/unblock {client}, POST /api/simulate {scenario}, POST /api/reset

## Structure
    run.py                 entry point
    sample_client.py       example integration
    app/detector.py        detection engine (rules + statistics)
    app/server.py          HTTP server, ingest + analytics API
    app/storage.py         SQLite persistence (abuse.db created on first run)
    app/simulator.py       normal traffic + 6 attack scenarios
    app/static/index.html  live dashboard
    tests/test_detector.py unit tests

## Prototype limits / next steps
In-memory sliding windows (single process), SQLite, no dashboard auth, rules + simple statistics.
For production: Redis for shared state, Kafka for ingestion, Postgres/ClickHouse for history,
auth + RBAC, and ML models (Isolation Forest, autoencoders).
