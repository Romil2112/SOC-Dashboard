# SOC Dashboard

SOC Dashboard is a Flask and PostgreSQL web app for triaging security alerts. It takes alerts over a REST API (log-analyzer pushes them, though any tool sending the right JSON works), holds them in a severity-ranked queue, and lets an analyst mark each one true positive, false positive, or escalation in a single click. It timestamps every action and turns those into SOC KPIs (MTTR, SLA-breach rate, escalation rate) drawn with Chart.js. It is the triage stage of a two-part pipeline: [log-analyzer](https://github.com/Romil2112/log-analyzer) detects the incidents, SOC Dashboard is where a person works them.

## Screenshots

Main dashboard: severity KPIs, category / severity / source charts, and the open-alert queue.

![SOC Dashboard main view](screenshots/dashboard.png)

The alert queue, with one-click triage on every alert.

![Alert queue](screenshots/alert-queue.png)

Analyst performance and the MTTR trend over the week.

![Analyst performance](screenshots/analyst-performance.png)

## How it works

Alerts reach the dashboard two ways and both land in one queue. A detector POSTs to the ingest endpoint with an API key; analysts sign in and work the queue in the browser. Every read and write goes through one PostgreSQL database holding three tables (alerts, analyst_actions, users), and `/api/stats` aggregates that into the charts and the SLA and MTTR numbers.

Security sits on a few specific choices. The ingest endpoint checks its API key with a constant-time comparison, so response timing does not reveal how much of the key was right. Analyst passwords are stored as bcrypt hashes and there is no self-registration: accounts are created from the CLI. Session routes sit behind CSRF protection, while the machine-to-machine ingest route is exempt because it authenticates by key rather than by cookie. Errors return JSON with a fixed message and no stack trace, so a failed request does not leak internal file paths.

`/api/stats` was the slow path. The stats endpoint used to run a correlated subquery once per alert row; I replaced it with a single aggregate join and the query went from 24ms to 12ms at 20,000 alerts. The rewrite scans analyst_actions once and LEFT JOINs it to alerts instead of re-querying per row, and the SLA and MTTR values it returns are unchanged.

## Features

- Severity-ranked alert queue (CRITICAL down to LOW) with one-click triage
- REST ingest API guarded by a constant-time `X-API-Key` check
- Flask-Login analyst auth, bcrypt-hashed passwords, no self-registration
- CSRF protection on session routes; JSON error handlers with no stack-trace leaks
- SOC KPIs: MTTR per analyst, SLA-breach rate per severity target, escalation rate
- Live filters by severity, detection source, and assignee that drive both the queue and the charts
- Chart.js views: alerts by category, by severity, by source, and a 7-day MTTR trend
- Fernet field-level encryption at rest for `title`, `source_ip`, and `description`
- Configurable retention purge (`ALERT_RETENTION_DAYS`)
- 50 pre-seeded demo alerts across 5 categories, 4 severities, and 5 detection sources
- 48 pytest tests at 95% line / 92% branch coverage, run against a real PostgreSQL

## Quick Start

Prerequisites: Python 3.12+ and PostgreSQL 14+.

Install:

```bash
pip install -r requirements.txt
```

Create and seed the database:

```bash
createdb soc_dashboard
psql soc_dashboard -f schema.sql
python seed.py
```

Copy `.env.example` to `.env` and set at least `FLASK_SECRET_KEY` (the app will not start without it) and `ALERTS_API_KEY` (required for ingest). Generate a value with `python -c "import secrets; print(secrets.token_hex(32))"`. Create an analyst account, then run the app:

```bash
python manage.py create-user alice 's0me-strong-passphrase' --role analyst
python app.py
```

The `create-user` line is how you create your login — there is no sign-up page, so run it before the first launch (use `--role admin` for full access). It listens on <http://localhost:8000>. `docker compose up` starts Flask and PostgreSQL together instead.

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main dashboard |
| GET | `/analyst` | Analyst performance page |
| GET | `/api/alerts` | Open alerts sorted by severity. Filterable: `?severity=&source=&assigned_to=` |
| GET | `/api/alerts/all` | All alerts. Same filter query params as above |
| POST | `/api/alerts` | **Ingest** a new alert `{title, category, severity, source?, source_ip?, description?}` → 201 |
| POST | `/api/alerts/<id>/classify` | Classify alert `{analyst, action}` |
| GET | `/api/stats` | Summary counts + `by_category` / `by_severity` / `by_source` + `escalation` + `sla` + MTTR by analyst + `assignees` |

`action` is one of `classify_tp` (→ `true_positive`), `classify_fp` (→ `false_positive`),
or `escalate` (→ `escalated`). Filter query params are validated against a column
whitelist, so they compose into parameterized SQL safely (no injection surface).

### Environment variables

Copy `.env.example` to `.env` and fill these in. The two required ones make the app refuse to start (or refuse ingest) if missing; the rest have safe defaults.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `FLASK_SECRET_KEY` | yes | — | Signs analyst login sessions; app won't start without it |
| `ALERTS_API_KEY` | for ingest | — | `X-API-Key` that `POST /api/alerts` checks (constant-time) |
| `DATABASE_URL` | — | `postgresql://localhost/soc_dashboard` | PostgreSQL connection string |
| `DB_ENCRYPTION_KEY` | — | unset (plaintext) | Enables Fernet encryption of title/source_ip/description at rest |
| `ALERT_RETENTION_DAYS` | — | `0` (keep forever) | Purge alerts older than N days at startup |
| `FLASK_DEBUG` | — | off | Set `1`/`true` for the Werkzeug debugger (local dev only) |
| `HOST` / `PORT` | — | `127.0.0.1` / `8000` | Bind address and port for `python app.py` |

## Architecture diagram

Two ways alerts arrive, one queue they land in. A detector (log-analyzer, or any tool) pushes alerts over the API-key-protected ingest endpoint; analysts sign in, work the queue, and classify each alert, which records an action and its response time. Everything reads and writes one PostgreSQL database, and the stats endpoint aggregates it into the charts and the SLA/MTTR numbers on the dashboard.

```mermaid
flowchart LR
    D[Detector<br/>e.g. log-analyzer] -->|POST /api/alerts<br/>X-API-Key| ING[Ingest]
    A[Analyst<br/>browser] -->|login session| WEB[Dashboard + queue]
    ING --> DB[(PostgreSQL<br/>alerts · analyst_actions · users)]
    WEB -->|classify / escalate| DB
    DB --> STATS[/api/stats<br/>counts · MTTR · SLA · escalation]
    STATS --> CHARTS[Chart.js dashboard]
    subgraph Security
        CSRF[CSRF on session routes]
        ENC[Fernet field encryption at rest]
    end
```

## Tests

48 pytest tests cover the ingest API, auth and CSRF, the classify/escalate flow, the KPI math (MTTR, SLA, escalation), the filter query params, encryption at rest, and the seed and user-management CLIs, at 95% line and 92% branch coverage. They run against a real PostgreSQL database through a Flask test client, both locally and on GitHub Actions with a Postgres service container. Point `DATABASE_URL` at a throwaway database and run:

```bash
python -m pytest tests/ -v
```

## ⚖️ Legal Notice & Responsible Use

This project is **free and open-source software**, released under the **MIT License** as a
**demonstration / learning / trial project**. It is provided **"as is", without warranty of
any kind**, and is **not an audited or certified commercial security product**.

- **Authorized use only.** Use it solely on systems, networks, and data that you own or are
  **explicitly authorized** to operate and analyze.
- **Do no harm.** Do not use it to surveil, stalk, harass, invade the privacy of, or conduct
  unauthorized monitoring of any person or organization.
- **Compliance is the operator's responsibility.** Alert data may include IP addresses and
  other details that qualify as personal data. Compliance with **GDPR, CCPA, HIPAA, and
  equivalent laws** — where applicable — rests with the operator.
- **Misuse may be illegal.** Unauthorized access to or monitoring of computer systems may
  violate laws such as the U.S. **CFAA**, the UK **Computer Misuse Act**, and EU
  information-systems directives.

By using this software you accept responsibility for operating it lawfully. See
[SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).
