# SOC Dashboard

Flask-based Security Operations Center analyst dashboard with real-time alert queue, MTTR tracking, and Chart.js visualizations.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?logo=bootstrap&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-4.4-FF6384?logo=chartdotjs&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Overview

**SOC Dashboard** is a triage console for security analysts. It surfaces security
alerts from a PostgreSQL database in a live, severity-ranked queue and lets analysts
classify each alert as a true positive, false positive, or escalation with a single
click. Every action is timestamped, so the system continuously measures **MTTR**
(mean time to resolve) per analyst and visualizes both the alert landscape and team
performance with Chart.js. The goal is to model the day-to-day workflow of a real SOC
analyst — what's in my queue, what's most urgent, and how fast is the team responding?

In a complete detection-and-response pipeline, this project is the **triage layer**.
It pairs with [**log-analyzer**](https://github.com/Romil2112/log-analyzer), the
**detection layer**, which ingests SSH `auth.log` files and runs both sliding-window
rule detection and an Isolation Forest ML model to generate alerts. Those alerts are
exactly the kind of events that land in this dashboard's queue. Together the two
projects demonstrate the full SOC pipeline: **Ingest → Detect → Triage → Respond.**

The intended users are **Tier 1 / Tier 2 SOC analysts** triaging incoming alerts, and
**SOC team leads / managers** who use the analyst-performance view to monitor MTTR
KPIs, spot bottlenecks, and understand workload distribution across the team. Because
it requires no login for the demo (the analyst name is stored client-side), it doubles
as a clear, hands-on teaching tool for the alert-triage workflow.

## Features

- **Real-time alert queue** pulled from PostgreSQL, sorted by severity (CRITICAL → LOW)
- **One-click triage:** True Positive / False Positive / Escalate buttons per alert
- **Analyst name saved to `localStorage`** — no login required for the demo
- **MTTR tracking** per analyst per day, with a 7-day trend chart
- **Color-coded performance table:** green &lt; 5 min, yellow 5–15 min, red &gt; 15 min
- **Alerts by category** doughnut chart (brute force, malware, phishing, port scan, anomaly)
- **Alerts by severity** bar chart (CRITICAL / HIGH / MEDIUM / LOW)
- **Auto-refresh every 30 seconds** via JavaScript polling
- **50 pre-seeded realistic alerts** across 5 categories and 4 severity levels
- **Docker support:** `docker compose up` starts Flask + PostgreSQL together
- **MIT Licensed**

## Screenshots

**Main dashboard — stat cards and charts**

![Dashboard](screenshots/dashboard.png)

**Open alert queue — severity badges and action buttons**

![Alert Queue](screenshots/alert-queue.png)

**Analyst performance — MTTR table and trend chart**

![Analyst Performance](screenshots/analyst-performance.png)

**MTTR trend per analyst — 7-day bar chart**

![MTTR Trend](screenshots/mttr-trend.png)

## Skills Demonstrated

| Area | Details |
|------|---------|
| Flask / Python | REST API design, route handling, psycopg2 direct DB access, no ORM |
| PostgreSQL | Schema design, JSONB-ready tables, timestamp-based MTTR aggregation |
| JavaScript | Fetch API polling, localStorage, dynamic DOM updates, Chart.js integration |
| Bootstrap 5 | Responsive dark-themed UI, badge system, card layout |
| SOC Domain Knowledge | Alert triage workflow, MTTR KPI, severity classification, analyst performance tracking |
| Docker | Multi-service Compose with health-checked PostgreSQL and volume mounts |
| Agentic AI Development | Built end-to-end using Claude Code with structured prompt engineering |

## How This Connects to log-analyzer

[**log-analyzer**](https://github.com/Romil2112/log-analyzer) is the **detection
layer** — it ingests SSH `auth.log` files, runs sliding-window rule detection and an
Isolation Forest ML model, and generates alerts. **soc-dashboard** is the **triage
layer** — analysts receive those alerts, classify them, and their response times are
tracked as MTTR. Together they demonstrate the full SOC pipeline:

**Ingest → Detect → Triage → Respond.**

## Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL 14+

### Install
```bash
pip3 install -r requirements.txt
```

### Setup database
```bash
createdb soc_dashboard
psql soc_dashboard -f schema.sql
python3 seed.py
```

### Run
```bash
python3 app.py
```

Open <http://localhost:8000>

### Docker
```bash
docker compose up
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main dashboard |
| GET | `/analyst` | Analyst performance page |
| GET | `/api/alerts` | Open alerts sorted by severity |
| GET | `/api/alerts/all` | All 50 alerts |
| POST | `/api/alerts/<id>/classify` | Classify alert `{analyst, action}` |
| GET | `/api/stats` | Summary stats + MTTR by analyst |

`action` is one of `classify_tp` (→ `true_positive`), `classify_fp` (→ `false_positive`),
or `escalate` (→ `escalated`).

## Project Structure

```
soc-dashboard/
├── app.py                 # Flask app: pages + REST API (psycopg2, no ORM)
├── schema.sql             # PostgreSQL schema: alerts + analyst_actions tables
├── seed.py                # Inserts 50 realistic demo alerts (+ analyst actions)
├── requirements.txt       # Python dependencies
├── .env.example           # Sample DATABASE_URL / config (copy to .env)
├── Dockerfile             # Flask app image (gunicorn)
├── docker-compose.yml     # Flask web + PostgreSQL 16 services
├── README.md              # This file
├── LICENSE                # MIT license
├── templates/             # Jinja2 templates
│   ├── base.html          #   Shared layout: dark navbar, Bootstrap + Chart.js CDNs
│   ├── dashboard.html     #   Stat cards, category/severity charts, alert queue table
│   └── analyst.html       #   MTTR performance table + 7-day trend chart
├── static/
│   └── dashboard.js       # Fetch polling, localStorage, Chart.js render/update
└── screenshots/           # README images
```

## License

MIT — see [LICENSE](LICENSE).
