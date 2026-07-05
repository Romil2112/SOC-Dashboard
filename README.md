# SOC Dashboard

A Flask and PostgreSQL dashboard where a security analyst works through alerts, triages them, and watches response-time numbers.

## What feeds it

Alerts come from [log-analyzer](https://github.com/Romil2112/log-analyzer). Its `--push-soc` flag POSTs each detected incident to `POST /api/alerts` here, and the alert lands in the open queue. Any tool that can send the right JSON with a valid API key can feed it, but log-analyzer is what it was built against.

## The queue

Alerts sort by severity, CRITICAL down to LOW. An analyst opens the queue and marks each one true positive, false positive, or escalate with a single click. Every action is timestamped, which is what the KPIs are built on.

## API security

The ingest endpoint checks its API key with a constant-time comparison, so response timing doesn't leak how much of the key was right. Session routes sit behind CSRF protection. Errors come back as JSON with no stack traces, so a failed request doesn't hand internal file paths to the caller.

## The /api/stats rewrite

`/api/stats` reports counts and SLA numbers across every alert. The first version ran a correlated subquery for each alert row to pull its matching action, so the database repeated the same lookup thousands of times over. I rewrote it as one aggregate join that groups the actions in a single pass. At 20,000 alerts the endpoint dropped from 24ms to 12ms, with the same output.

## KPIs

It tracks three things per analyst: MTTR (mean time to resolve), SLA-breach rate against per-severity response targets, and escalation rate, the share of triaged alerts sent on to incident response. Chart.js draws them, and the queue and charts both filter live by severity, detection source, and assignee.

## Tests

48 pytest tests at 95% line and 92% branch coverage. They run against a real PostgreSQL database, not a mock, through a Flask test client on GitHub Actions with a Postgres service container.

## Running it locally

```bash
pip install -r requirements.txt
createdb soc_dashboard
psql soc_dashboard -f schema.sql
python seed.py
```

Set `FLASK_SECRET_KEY` and `ALERTS_API_KEY` in a `.env` file (the app won't start without the secret key), create an analyst account with `python manage.py create-user alice 'passphrase' --role analyst`, then:

```bash
python app.py
```

It listens on <http://localhost:8000>. `docker compose up` starts Flask and PostgreSQL together instead.
