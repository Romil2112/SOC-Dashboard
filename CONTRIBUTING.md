# Contributing to SOC Dashboard

SOC Dashboard is an open-source Flask + PostgreSQL SOC analytics dashboard, and contributions are welcome. Whether you are fixing a bug, adding a new KPI, improving the frontend, or tightening up the docs — this guide has everything you need to get started.

## Ways to contribute

- **Bug reports** — something behaves incorrectly or throws an unexpected error
- **New KPI widgets** — additional SOC metrics beyond MTTR, SLA breach rate, and escalation rate
- **New chart types** — additional Chart.js visualisations driven by `/api/stats`
- **New API endpoints** — extending the REST surface (e.g. alert assignment, bulk actions)
- **Frontend improvements** — UX, filtering, accessibility, responsiveness
- **Database schema changes** — new tables or columns that extend the data model
- **Security hardening** — see [SECURITY.md](SECURITY.md) for vulnerability reports
- **Documentation** — clearer setup steps, architecture notes, API examples

## Getting started

**Prerequisites:** Python 3.12+, PostgreSQL 14+.

```bash
# 1. Clone and create a virtual environment
git clone https://github.com/Romil2112/SOC-Dashboard.git
cd SOC-Dashboard
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install runtime + dev dependencies
pip install -r requirements-dev.txt

# 3. Create and initialise the database
createdb soc_dashboard
psql soc_dashboard -f schema.sql

# 4. Seed 50 demo alerts
python seed.py

# 5. Configure secrets
cp .env.example .env
# Open .env and fill in:
#   FLASK_SECRET_KEY — generate with: python -c "import secrets; print(secrets.token_hex(32))"
#   ALERTS_API_KEY   — same command; used by POST /api/alerts

# 6. Create a local analyst account (no self-registration in the app)
python manage.py create-user alice 'your-passphrase' --role analyst

# 7. Start the dev server
python app.py
# → http://localhost:8000
```

### Docker alternative

```bash
cp .env.example .env   # set FLASK_SECRET_KEY and ALERTS_API_KEY
docker compose up
```

`docker-compose.yml` starts PostgreSQL, applies `schema.sql`, and starts Flask — no separate database setup needed.

### Test database

Tests need their own throwaway database. Spin one up with Docker:

```bash
docker run -d --name soc-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=soc_test \
  -p 5433:5432 postgres:16

export DATABASE_URL=postgresql://postgres:postgres@localhost:5433/soc_test
```

`tests/conftest.py` drops and recreates the schema before each test run, so this database can be reused safely.

## Project structure

```
app.py          — Flask application: all routes, auth, CSRF, DB queries
schema.sql      — PostgreSQL schema (alerts, analyst_actions, users tables)
manage.py       — CLI: create-user subcommand (bcrypt-hashed, no self-registration)
seed.py         — loads 50 demo alerts across 5 categories, 4 severities, 5 sources
crypto.py       — optional Fernet field-level encryption for title/source_ip/description
templates/
  base.html     — shared layout, Chart.js import, nav
  dashboard.html — main dashboard: KPI cards, charts, alert queue
  analyst.html  — analyst performance page: MTTR trend and per-analyst breakdown
  login.html    — login form
static/
  dashboard.js  — Chart.js wiring: fetches /api/stats, /api/alerts, renders charts + queue
tests/
  conftest.py   — fixtures: clean schema + deterministic alerts + test analyst per run
  test_app.py   — ingest API, classify/escalate flow, filter query params, stats math
  test_crypto.py — Fernet encrypt/decrypt round-trips
  test_manage.py — create-user CLI happy path and error cases
  test_security.py — CSRF enforcement, auth boundaries, constant-time key check
  test_seed.py  — seed.py idempotency and row counts
```

## How to add a new API endpoint and chart

This is the most common contribution type. The pattern used throughout the codebase:

**1. Add a SQL query in `app.py`**

All database work is raw psycopg2 — no ORM. Open a connection with `get_db()`, run a parameterised query, and return JSON:

```python
@app.get("/api/alerts/by_analyst")
@login_required
def alerts_by_analyst():
    with get_db() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT assigned_to, count(*) AS total
            FROM alerts
            WHERE assigned_to IS NOT NULL
            GROUP BY assigned_to
            ORDER BY total DESC
        """)
        return jsonify(cur.fetchall())
```

**2. Expose the data from `/api/stats` if it belongs there**, or add a new dedicated endpoint like the example above. Stats that feed dashboard KPIs belong in `/api/stats`; per-entity breakdowns can be separate endpoints.

**3. Wire a Chart.js chart in `static/dashboard.js`**

```js
fetch('/api/alerts/by_analyst')
  .then(r => r.json())
  .then(data => {
    new Chart(document.getElementById('byAnalystChart'), {
      type: 'bar',
      data: {
        labels: data.map(d => d.assigned_to),
        datasets: [{ label: 'Alerts', data: data.map(d => d.total) }]
      }
    });
  });
```

**4. Add a `<canvas id="byAnalystChart">` element** in the relevant template (`dashboard.html` or `analyst.html`).

**5. Write tests** — add a test in `tests/test_app.py` that calls the endpoint with the `client` fixture and asserts on the response shape and values against the deterministic fixture data defined in `conftest.py`.

## Database schema changes

The project uses plain SQL migrations, not an ORM migration framework. For any schema change:

1. Update `schema.sql` — this is the source of truth and is re-applied on every test run
2. Write a standalone migration SQL file if you need to document the upgrade path for existing deployments (e.g. `migrations/0002_add_analyst_notes.sql`)
3. Update `seed.py` if the new columns need demo data
4. Update `tests/conftest.py` fixture data if the change affects the deterministic test rows

Do not add nullable columns with no default without discussing it in the issue first — the test fixtures use explicit column lists and will break if the schema diverges.

## Code style

The project uses **ruff** (100-character line length) and **mypy**:

```bash
# Format / lint
ruff check .
ruff format .

# Type check
mypy app.py
```

Configuration is in `pyproject.toml`. The selected ruff rules are E, W, F (pyflakes), I (isort), N (pep8-naming), UP (pyupgrade), B (bugbear). `tests/*` is exempt from N802/N806.

No `black` is used in this project — use `ruff format` instead.

## Running tests

Tests run against a real PostgreSQL database (not a mock). Set `DATABASE_URL` first (see "Test database" above), then:

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ -v --cov=. --cov-report=term-missing

# Run a single test file
python -m pytest tests/test_app.py -v
```

The test suite covers the ingest API, auth, CSRF, classify/escalate flow, KPI math, filter query params, encryption, and the `manage.py` / `seed.py` CLIs — 48 tests at 95% line / 92% branch coverage. New contributions should maintain or improve that coverage.

## PR guidelines

- **One concern per PR.** A new chart and a schema change should be two separate PRs.
- **Tests are required.** Every new endpoint or behaviour change needs a test in the matching `test_*.py` file using the existing fixtures.
- **No breaking API changes without discussion.** `/api/stats`, `/api/alerts`, and `/api/alerts/<id>/classify` are consumed by log-analyzer. Changing their shape requires an issue discussion first.
- **Run the full suite locally before opening a PR.** CI runs the same `pytest` command against a PostgreSQL service container.
- **Security-sensitive changes** (auth, CSRF, API key handling, encryption) need extra scrutiny — flag them clearly in the PR description.

## Reporting bugs

Open an issue and include:

- What you did, what you expected, and what actually happened
- Browser and version (for frontend bugs)
- Python version (`python --version`)
- Flask version (`pip show flask | grep Version`)
- PostgreSQL version (`psql --version`)
- Relevant log output or error message (redact any secrets or IP addresses)
- Whether you are running locally or via Docker Compose

See [SECURITY.md](SECURITY.md) for vulnerabilities — do not open a public issue for security bugs.
