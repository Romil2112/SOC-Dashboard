"""SOC Analyst Dashboard — Flask + psycopg2 (no ORM)."""
import hmac
import os
from datetime import datetime, timezone

import bcrypt
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect

from crypto import decrypt_field, encrypt_field, get_fernet

load_dotenv()

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://localhost/soc_dashboard"
)

app = Flask(__name__)

# Secret key is mandatory: Flask sessions (and therefore analyst login) are
# unsafe without it. Read at import so a misconfigured deployment fails fast
# with an actionable message instead of a cryptic session error later.
# (Tests set this in tests/conftest.py before importing app.)
_secret = os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "FLASK_SECRET_KEY is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret

# CSRF protection for the session-authenticated, cookie-based routes (the login
# form and the analyst classify action). The machine-to-machine ingest endpoint
# is exempted below: it carries no session cookie and is authenticated by a
# constant-time X-API-Key check instead, so CSRF does not apply to it.
csrf = CSRFProtect(app)

# API key required to ingest alerts machine-to-machine (POST /api/alerts).
ALERTS_API_KEY = os.environ.get("ALERTS_API_KEY")

# Number of days to retain alerts (0 = retain forever). Purged once at startup.
ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", "0") or "0")

# Optional field-level encryption at rest. When DB_ENCRYPTION_KEY is unset,
# FERNET is None and these columns are stored/returned as plaintext.
FERNET = get_fernet()
# Alert columns that may carry PII / host data. None are used in
# WHERE/GROUP BY/ORDER BY, so encrypting them does not affect any filter,
# chart, or aggregate.
_ENCRYPTED_ALERT_FIELDS = ("title", "source_ip", "description")
print(
    "[+] Field encryption ACTIVE (DB_ENCRYPTION_KEY set)" if FERNET
    else "[*] Field encryption DISABLED — set DB_ENCRYPTION_KEY to encrypt PII at rest"
)

# --------------------------------------------------------------------------- #
# Authentication (Flask-Login)
# --------------------------------------------------------------------------- #
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin):
    """A dashboard account loaded from the users table."""

    def __init__(self, user_id, username, role):
        self.id = str(user_id)
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login callback: load the User for a session's user id, or None."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, username, role FROM users WHERE id = %s", (user_id,)
        )
        row = cur.fetchone()
    if row is None:
        return None
    return User(row["id"], row["username"], row["role"])

# Severity ordering used for queue sorting (CRITICAL first).
SEVERITY_RANK = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

# Map a classify action to the resulting alert status.
ACTION_TO_STATUS = {
    "classify_tp": "true_positive",
    "classify_fp": "false_positive",
    "escalate": "escalated",
}

# Per-severity response-time SLA targets (seconds). An alert breaches SLA when
# its time-to-triage (or current age, if still open) exceeds the target.
SLA_SECONDS = {
    "CRITICAL": 15 * 60,       # 15 minutes
    "HIGH":     60 * 60,       # 1 hour
    "MEDIUM":   4 * 60 * 60,   # 4 hours
    "LOW":      24 * 60 * 60,  # 24 hours
}


def compute_sla(rows):
    """Given rows of {severity, resp, created_at}, return SLA breach metrics.

    resp = recorded triage response time (seconds) or None if still open
    (in which case the alert's current age is used).
    """
    now_ts = datetime.now(timezone.utc)
    considered = breaches = 0
    by_severity = {}
    for r in rows:
        target = SLA_SECONDS.get(r["severity"])
        if target is None:
            continue
        considered += 1
        elapsed = r["resp"] if r["resp"] is not None else (now_ts - r["created_at"]).total_seconds()
        if elapsed > target:
            breaches += 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
    rate = round(100 * breaches / considered, 1) if considered else 0.0
    return {
        "breaches": breaches,
        "considered": considered,
        "breach_rate": rate,
        "by_severity": by_severity,
    }


def get_conn():
    """Open a new connection with dict-style rows."""
    return psycopg2.connect(
        DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor
    )


def serialize(row):
    """Convert datetime/date values in a row dict to ISO strings."""
    out = {}
    for key, value in row.items():
        if hasattr(value, "isoformat"):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out


def decrypt_alert(row):
    """Decrypt the sensitive fields of an alert row in place, then return it.

    Safe when encryption is disabled or the row predates encryption: the
    underlying decrypt_field passes plaintext through unchanged.
    """
    for field in _ENCRYPTED_ALERT_FIELDS:
        if field in row:
            row[field] = decrypt_field(FERNET, row[field])
    return row


def purge_old_alerts(days):
    """Delete alerts (and cascaded analyst_actions) older than `days`.

    No-op when days <= 0. Returns the number of alerts deleted.
    """
    if days <= 0:
        return 0
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM alerts WHERE created_at < now() - make_interval(days => %s)",
            (days,),
        )
        deleted = cur.rowcount
        conn.commit()
    return deleted


# Columns the alert-list endpoints can be filtered on, mapped to their request
# query-parameter names. Only these are honored, so the filter is injection-safe.
FILTER_COLUMNS = {"severity": "severity", "source": "source", "assigned_to": "assigned_to"}


def _query_param_filters():
    """(clauses, values) for the whitelisted severity/source/assignee filters."""
    where_sql, params = [], []
    for param, column in FILTER_COLUMNS.items():
        value = (request.args.get(param) or "").strip()
        if value:
            where_sql.append(f"{column} = %s")
            params.append(value)
    return where_sql, params


def alert_filters(extra=None):
    """Build a parameterized WHERE clause from the request's query string.

    Returns (sql, params). `extra` is a list of pre-baked ("col = %s", value)
    predicates (e.g. the open-queue's status filter) merged with user filters.
    """
    clauses = list(extra or [])
    where_sql = [c for c, _ in clauses]
    params = [v for _, v in clauses]
    extra_sql, extra_params = _query_param_filters()
    where_sql += extra_sql
    params += extra_params
    sql = (" WHERE " + " AND ".join(where_sql)) if where_sql else ""
    return sql, params


# Shared severity ordering used by every alert query (CRITICAL first, then age).
_SEVERITY_ORDER = """
    ORDER BY CASE severity
                 WHEN 'CRITICAL' THEN 1
                 WHEN 'HIGH'     THEN 2
                 WHEN 'MEDIUM'   THEN 3
                 WHEN 'LOW'      THEN 4
                 ELSE 5
             END,
             created_at DESC
"""


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #
# Return clean JSON for the API instead of Flask's default HTML error pages,
# and never leak a stack trace or internal detail to the client. The 4xx
# handlers echo the abort() description (which is analyst-facing and safe); the
# 500 handler returns a fixed generic message so an unexpected exception can't
# surface internals even if debug is ever left on.
def _json_error(err):
    code = getattr(err, "code", 500)
    return jsonify({"error": getattr(err, "description", "error")}), code


for _code in (400, 401, 403, 404, 405, 409):
    app.register_error_handler(_code, _json_error)


@app.errorhandler(500)
def _handle_500(err):
    return jsonify({"error": "internal server error"}), 500


# --------------------------------------------------------------------------- #
# Auth routes
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    """Analyst login. No self-registration — accounts come from manage.py."""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, role, password_hash "
                "FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
        if row and bcrypt.checkpw(
            password.encode("utf-8"), row["password_hash"].encode("utf-8")
        ):
            login_user(User(row["id"], row["username"], row["role"]))
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Log the analyst out and redirect to the login page."""
    logout_user()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.route("/")
@login_required
def dashboard():
    """Render the main SOC dashboard page (charts + open-alert queue)."""
    return render_template("dashboard.html")


@app.route("/analyst")
@login_required
def analyst():
    """Render the per-analyst metrics page."""
    return render_template("analyst.html")


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def _list_alerts(where_sql, params):
    """Run the shared alert-list query and return decrypted, serialized rows."""
    with get_conn() as conn, conn.cursor() as cur:
        # nosec B608: where_sql is assembled only from the whitelisted
        # FILTER_COLUMNS names; every value is bound as a parameter.
        cur.execute("SELECT * FROM alerts" + where_sql + _SEVERITY_ORDER, params)  # nosec B608
        rows = cur.fetchall()
    return [serialize(decrypt_alert(r)) for r in rows]


@app.route("/api/alerts")
@login_required
def api_open_alerts():
    """Open queue, optionally filtered by severity/source/assignee.

    CRITICAL -> LOW then newest first.
    """
    where_sql, params = alert_filters(extra=[("status = %s", "open")])
    return jsonify(_list_alerts(where_sql, params))


@app.route("/api/alerts/all")
@login_required
def api_all_alerts():
    """Every alert, optionally filtered by severity/source/assignee.

    CRITICAL -> LOW then newest first.
    """
    where_sql, params = alert_filters()
    return jsonify(_list_alerts(where_sql, params))


def _valid_api_key():
    """True if the request carries the configured X-API-Key (constant-time)."""
    provided = request.headers.get("X-API-Key", "")
    return bool(ALERTS_API_KEY) and hmac.compare_digest(provided, ALERTS_API_KEY)


def _parse_ingest_payload(body):
    """Pull title/category/severity from an ingest body, aborting 400 if invalid."""
    title    = (body.get("title") or "").strip()
    category = (body.get("category") or "").strip()
    severity = (body.get("severity") or "").strip().upper()
    if not title or not category:
        abort(400, description="title and category are required")
    if severity not in SEVERITY_RANK:
        abort(400, description="severity must be CRITICAL, HIGH, MEDIUM or LOW")
    return title, category, severity


def _ingest_values(body, title, category, severity):
    """Build the INSERT parameter tuple, encrypting the PII columns at rest."""
    return (
        encrypt_field(FERNET, title), category, severity,
        body.get("source") or None,
        encrypt_field(FERNET, body.get("source_ip") or None),
        encrypt_field(FERNET, body.get("description") or None),
    )


@app.route("/api/alerts", methods=["POST"])
@csrf.exempt
def api_ingest_alert():
    """Ingest a new alert into the open queue.

    This is the machine-to-machine entry point that lets an upstream detector
    (e.g. log-analyzer) push real incidents into the dashboard. It is NOT behind
    analyst login; instead it requires a valid X-API-Key header.
    """
    if not _valid_api_key():
        return jsonify({"error": "missing or invalid X-API-Key"}), 401

    body = request.get_json(silent=True) or {}
    title, category, severity = _parse_ingest_payload(body)

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (title, category, severity, source, source_ip, description, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'open')
            RETURNING *
            """,
            _ingest_values(body, title, category, severity),
        )
        created = cur.fetchone()

    return jsonify(serialize(decrypt_alert(created))), 201


@app.route("/api/alerts/<int:alert_id>/classify", methods=["POST"])
@login_required
def api_classify(alert_id):
    """Classify an alert: update status, record the analyst action + MTTR."""
    body = request.get_json(silent=True) or {}
    analyst_name = (body.get("analyst") or "").strip()
    action = body.get("action")

    if not analyst_name:
        abort(400, description="analyst is required")
    if action not in ACTION_TO_STATUS:
        abort(400, description="action must be classify_tp, classify_fp or escalate")

    new_status = ACTION_TO_STATUS[action]

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
        alert = cur.fetchone()
        if alert is None:
            abort(404, description="alert not found")
        if alert["status"] != "open":
            abort(409, description="alert is already closed")

        # Update the alert's status and assignee.
        cur.execute(
            """
            UPDATE alerts
            SET status = %s, assigned_to = %s
            WHERE id = %s
            RETURNING *
            """,
            (new_status, analyst_name, alert_id),
        )
        updated = decrypt_alert(cur.fetchone())

        # Record the action with a response time measured from alert creation.
        cur.execute(
            """
            INSERT INTO analyst_actions
                (alert_id, analyst_name, action, response_time_seconds)
            VALUES
                (%s, %s, %s,
                 GREATEST(0, EXTRACT(EPOCH FROM (now() - %s))::int))
            """,
            (alert_id, analyst_name, action, alert["created_at"]),
        )

    return jsonify(serialize(updated))


@app.route("/api/stats")
@login_required
def api_stats():
    """Aggregate counts plus per-analyst, per-day MTTR."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) AS c FROM alerts")
        total = cur.fetchone()["c"]

        cur.execute("SELECT count(*) AS c FROM alerts WHERE status = 'open'")
        open_count = cur.fetchone()["c"]

        closed = total - open_count

        cur.execute(
            "SELECT category, count(*) AS c FROM alerts GROUP BY category"
        )
        by_category = {r["category"]: r["c"] for r in cur.fetchall()}

        cur.execute(
            "SELECT severity, count(*) AS c FROM alerts GROUP BY severity"
        )
        by_severity = {r["severity"]: r["c"] for r in cur.fetchall()}

        # Detection-source breakdown (the sensor/tool that raised each alert).
        cur.execute(
            "SELECT coalesce(source, 'unknown') AS source, count(*) AS c "
            "FROM alerts GROUP BY source"
        )
        by_source = {r["source"]: r["c"] for r in cur.fetchall()}

        # Escalation KPI: of the alerts an analyst has triaged (anything no
        # longer 'open'), what share were escalated to incident response?
        cur.execute(
            """
            SELECT count(*) FILTER (WHERE status = 'escalated')  AS escalated,
                   count(*) FILTER (WHERE status <> 'open')      AS triaged
            FROM alerts
            """
        )
        esc = cur.fetchone()
        escalated, triaged = esc["escalated"], esc["triaged"]
        escalation = {
            "escalated": escalated,
            "triaged": triaged,
            "rate": round(100 * escalated / triaged, 1) if triaged else 0.0,
        }

        # Distinct assignees, for populating the dashboard filter control.
        cur.execute(
            "SELECT DISTINCT assigned_to FROM alerts "
            "WHERE assigned_to IS NOT NULL ORDER BY assigned_to"
        )
        assignees = [r["assigned_to"] for r in cur.fetchall()]

        # Per-analyst, per-day average response time over the last 7 days.
        cur.execute(
            """
            SELECT analyst_name AS analyst,
                   acted_at::date AS date,
                   round(avg(response_time_seconds))::int AS avg_seconds,
                   count(*) AS count
            FROM analyst_actions
            WHERE response_time_seconds IS NOT NULL
              AND acted_at >= now() - interval '7 days'
            GROUP BY analyst_name, acted_at::date
            ORDER BY date, analyst
            """
        )
        mttr_by_analyst = [serialize(r) for r in cur.fetchall()]

        # SLA inputs: each alert's severity, age, and (earliest) triage response
        # time. Aggregate the actions once and LEFT JOIN, rather than running a
        # correlated subquery per alert — ~2x faster on a large alerts table and
        # it scales better as the queue grows.
        cur.execute(
            """
            SELECT a.severity,
                   a.created_at,
                   m.resp
            FROM alerts a
            LEFT JOIN (
                SELECT alert_id, min(response_time_seconds) AS resp
                FROM analyst_actions
                GROUP BY alert_id
            ) m ON m.alert_id = a.id
            """
        )
        sla_rows = cur.fetchall()

    sla = compute_sla(sla_rows)

    return jsonify(
        {
            "total": total,
            "open": open_count,
            "closed": closed,
            "by_category": by_category,
            "by_severity": by_severity,
            "by_source": by_source,
            "escalation": escalation,
            "assignees": assignees,
            "mttr_by_analyst": mttr_by_analyst,
            "sla": sla,
        }
    )


# Enforce retention once at startup (covers both `python app.py` and gunicorn
# import). Guarded so an unreachable DB at boot never crashes the app.
if ALERT_RETENTION_DAYS > 0:
    try:
        _purged = purge_old_alerts(ALERT_RETENTION_DAYS)
        print(f"[+] Retention: purged {_purged} alert(s) older than "
              f"{ALERT_RETENTION_DAYS} day(s)")
    except Exception as exc:  # pragma: no cover - boot-time best effort
        print(f"[!] Retention purge skipped: {exc}")


if __name__ == "__main__":
    # Debug and bind address come from the environment so production never runs
    # the Werkzeug debugger or binds every interface by accident. Defaults are
    # safe: debugger off, loopback only. Set FLASK_DEBUG=1 for local dev and
    # HOST=0.0.0.0 when you genuinely need to expose the port (e.g. in Docker).
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes", "on")
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("PORT", 8000)), debug=debug)
