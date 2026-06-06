# soc-dashboard

A SOC (Security Operations Center) analyst dashboard built with **Flask + PostgreSQL
+ Chart.js + Bootstrap 5**. It presents a live alert-triage queue, lets analysts
classify alerts (true positive / false positive / escalate), and tracks per-analyst
**MTTR** (mean time to resolve) over the last 7 days.

![stack](https://img.shields.io/badge/stack-Flask%20%7C%20PostgreSQL%20%7C%20Chart.js-blue)

## Features

- **Live alert queue** — open alerts sorted CRITICAL → LOW, auto-refreshing every 30s.
- **One-click triage** — classify each alert as TP / FP / Escalate; the action and a
  computed response time are recorded against the analyst.
- **Real-time stats** — total / open / closed-today counts and average MTTR today.
- **Visualizations** — doughnut chart by category, bar chart by severity (Chart.js 4.4).
- **Analyst performance page** — per-analyst, per-day table (color-coded by speed) plus a
  7-day MTTR trend bar chart.
- **Seeded demo data** — 50 realistic alerts across 5 categories and 4 severities.
- **Dockerized** — `docker compose up` brings up Flask + Postgres, schema-loaded and seeded.

## Skills Demonstrated

| Area | What it shows |
|------|---------------|
| Backend | Flask app with a clean REST API, **psycopg2 used directly (no ORM)** |
| SQL | Hand-written schema, `CASE`-based severity sorting, `GROUP BY` aggregations, date bucketing for MTTR |
| Data modeling | Normalized `alerts` + `analyst_actions` with FK + indexes |
| Frontend | Bootstrap 5 dark UI, Chart.js doughnut/bar charts, vanilla-JS polling |
| Security domain | Realistic SOC alert taxonomy (brute force, malware, phishing, port scan, anomaly) and triage workflow + MTTR metrics |
| DevOps | Multi-stage-friendly Dockerfile, docker-compose with healthcheck + auto-seed |

## Quick Start (local)

Requires Python 3.10+ and a running PostgreSQL.

```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Configure the DB connection
cp .env.example .env        # edit DATABASE_URL if needed

# 3. Create + initialize the database
createdb soc_dashboard
psql soc_dashboard -f schema.sql

# 4. Seed 50 alerts
python3 seed.py

# 5. Run
python3 app.py              # http://localhost:8000
```

## Docker

```bash
docker compose up --build
# Dashboard: http://localhost:8000
```

The `db` service loads `schema.sql` on first init; the `web` service runs `seed.py`
once Postgres is healthy, then serves via gunicorn.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Dashboard page (alert queue + charts) |
| `GET`  | `/analyst` | Analyst performance page |
| `GET`  | `/api/alerts` | Open alerts, sorted CRITICAL → LOW |
| `GET`  | `/api/alerts/all` | All alerts |
| `POST` | `/api/alerts/<id>/classify` | Body `{ "analyst": "alice", "action": "classify_tp" }` — updates status, records action + response time, returns the updated alert |
| `GET`  | `/api/stats` | `{ total, open, closed, by_category, by_severity, mttr_by_analyst[] }` |

`action` is one of `classify_tp` (→ `true_positive`), `classify_fp` (→ `false_positive`),
`escalate` (→ `escalated`).

### Example

```bash
curl -s localhost:8000/api/stats | jq
curl -s -X POST localhost:8000/api/alerts/1/classify \
  -H 'Content-Type: application/json' \
  -d '{"analyst":"alice","action":"classify_tp"}'
```

## Data Model

- **alerts** — `id, title, category, severity, source_ip, description, created_at, status, assigned_to`
- **analyst_actions** — `id, alert_id → alerts, analyst_name, action, acted_at, response_time_seconds`

## License

MIT
