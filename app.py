"""SOC Analyst Dashboard — Flask + psycopg2 (no ORM)."""
import hmac
import json
import logging
import os
import queue
import threading
from datetime import date, datetime, timezone
from functools import wraps

import bcrypt
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
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
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect

from crypto import decrypt_field, encrypt_field, get_fernet

load_dotenv()

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Redis (optional) — SSE pub/sub and distributed state
# --------------------------------------------------------------------------- #
_REDIS_URL = os.environ.get("REDIS_URL")
_REDIS_CLIENT = None
_REDIS_SSE_CHANNEL = "soc:alerts"

if _REDIS_URL:
    try:
        import redis as _redis_module
        _REDIS_CLIENT = _redis_module.from_url(_REDIS_URL, socket_timeout=2)
        print(f"[+] Redis SSE pub/sub enabled (url={_REDIS_URL})")
    except ImportError:
        print("[!] redis-py not installed; SSE falling back to in-process queue "
              "(pip install redis)")

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
# Semantic embedding (fastembed + pgvector)
# --------------------------------------------------------------------------- #
_EMBEDDING_MODEL = None
_EMBEDDING_LOAD_FAILED = "unavailable"  # sentinel — set after a failed load attempt


def _get_embedding_model():
    """Load fastembed TextEmbedding on first call; return None if unavailable.

    On failure the sentinel _EMBEDDING_LOAD_FAILED is stored so subsequent
    calls skip the (potentially slow) download attempt instead of retrying.
    """
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None:
        try:
            from fastembed import TextEmbedding
            _EMBEDDING_MODEL = TextEmbedding("BAAI/bge-small-en-v1.5")
        except Exception as exc:
            logger.warning(
                "fastembed model load failed — semantic similarity disabled: %s", exc
            )
            _EMBEDDING_MODEL = _EMBEDDING_LOAD_FAILED
    return None if _EMBEDDING_MODEL is _EMBEDDING_LOAD_FAILED else _EMBEDDING_MODEL


def _embeddings_available() -> bool:
    """True unless the embedding model previously failed to load."""
    return _EMBEDDING_MODEL is not _EMBEDDING_LOAD_FAILED


def _embed_text(text):
    """Return a pgvector literal string for text, or None if model is unavailable."""
    model = _get_embedding_model()
    if model is None:
        return None
    vec = next(model.embed([text]))
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


# --------------------------------------------------------------------------- #
# Role-based access control
# --------------------------------------------------------------------------- #
def require_role(*roles):
    """Decorator: require current_user.role to be in roles, or abort 403."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403, description="insufficient role")
            return f(*args, **kwargs)
        return wrapped
    return decorator


# --------------------------------------------------------------------------- #
# In-process pub/sub for Server-Sent Events
# (Redis pub/sub is used instead when _REDIS_CLIENT is set)
# --------------------------------------------------------------------------- #
_sse_subscribers: list = []
_sse_lock = threading.Lock()


def _sse_publish(event: dict) -> None:
    """Broadcast an event dict to all SSE subscribers.

    When Redis is configured, publishes to _REDIS_SSE_CHANNEL so every worker
    process receives the event. Falls back to the in-process queue otherwise.
    """
    if _REDIS_CLIENT is not None:
        _REDIS_CLIENT.publish(_REDIS_SSE_CHANNEL, json.dumps(event))
        return
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)


def _sse_subscribe():
    q = queue.Queue(maxsize=100)
    with _sse_lock:
        _sse_subscribers.append(q)
    return q


def _sse_unsubscribe(q) -> None:
    with _sse_lock:
        if q in _sse_subscribers:
            _sse_subscribers.remove(q)


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

# ATT&CK Navigator: map SOC alert categories to MITRE technique IDs.
_CATEGORY_MITRE: dict[str, str] = {
    "brute_force": "T1110.001",
    "port_scan":   "T1046",
    "malware":     "T1059",
    "phishing":    "T1566",
    "anomaly":     "T1078",
}

# Score used in the Navigator layer; higher severity → higher heat.
_NAVIGATOR_SCORE: dict[str, int] = {
    "CRITICAL": 100,
    "HIGH":      75,
    "MEDIUM":    50,
    "LOW":       25,
}

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
    return {
        key: value.isoformat() if isinstance(value, (datetime, date)) else value
        for key, value in row.items()
    }


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


def alert_filters(extra=None):
    """Build a parameterized WHERE clause from the request's query string.

    Returns (sql, params). `extra` is a list of pre-baked ("col = %s", value)
    predicates (e.g. the open-queue's status filter) merged with user filters.
    """
    clauses = list(extra or [])
    where_sql = [c for c, _ in clauses]
    params = [v for _, v in clauses]
    for param, column in FILTER_COLUMNS.items():
        value = (request.args.get(param) or "").strip()
        if value:
            where_sql.append(f"{column} = %s")
            params.append(value)
    # created_after: ISO datetime string (additive param, no existing filter affected)
    created_after = (request.args.get("created_after") or "").strip()
    if created_after:
        try:
            datetime.fromisoformat(created_after.replace("Z", "+00:00"))
        except ValueError:
            abort(400, description="created_after must be an ISO 8601 datetime")
        where_sql.append("created_at >= %s")
        params.append(created_after)
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
def _parse_pagination():
    """Parse and validate page/per_page from the request query string.

    Defaults: page=1, per_page=100. Aborts 400 on non-integer or out-of-range values.
    per_page is capped at 500 to prevent unbounded result sets.
    """
    try:
        page = int(request.args.get("page", 1))
    except (ValueError, TypeError):
        abort(400, description="page must be a positive integer")
    try:
        per_page = int(request.args.get("per_page", 100))
    except (ValueError, TypeError):
        abort(400, description="per_page must be an integer between 1 and 500")
    if page < 1:
        abort(400, description="page must be >= 1")
    if per_page < 1 or per_page > 500:
        abort(400, description="per_page must be between 1 and 500")
    return page, per_page


def _list_alerts(where_sql, params, page: int, per_page: int) -> dict:
    """Run the shared alert-list query and return a paginated envelope.

    The COUNT uses the same WHERE clause so ``total`` reflects the filtered
    set, not the whole table.
    """
    offset = (page - 1) * per_page
    with get_conn() as conn, conn.cursor() as cur:
        # nosec B608: where_sql is assembled only from the whitelisted
        # FILTER_COLUMNS names; every value is bound as a parameter.
        cur.execute("SELECT count(*) AS c FROM alerts" + where_sql, params)  # nosec B608
        total = cur.fetchone()["c"]
        cur.execute(  # nosec B608
            "SELECT * FROM alerts" + where_sql + _SEVERITY_ORDER + " LIMIT %s OFFSET %s",
            params + [per_page, offset],
        )
        rows = cur.fetchall()
    alerts = [serialize(decrypt_alert(r)) for r in rows]
    total_pages = (total + per_page - 1) // per_page if total else 0
    return {
        "alerts": alerts,
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
    }


@app.route("/api/alerts")
@login_required
def api_open_alerts():
    """Open queue, optionally filtered by severity/source/assignee.

    CRITICAL -> LOW then newest first. Paginated: page/per_page params
    (default page=1, per_page=100, max per_page=500).
    """
    page, per_page = _parse_pagination()
    where_sql, params = alert_filters(extra=[("status = %s", "open")])
    return jsonify(_list_alerts(where_sql, params, page, per_page))


@app.route("/api/alerts/all")
@login_required
def api_all_alerts():
    """Every alert, optionally filtered by severity/source/assignee.

    CRITICAL -> LOW then newest first. Paginated: page/per_page params
    (default page=1, per_page=100, max per_page=500).
    """
    page, per_page = _parse_pagination()
    where_sql, params = alert_filters()
    return jsonify(_list_alerts(where_sql, params, page, per_page))


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
    """Build the INSERT parameter tuple, encrypting the PII columns at rest.

    workflow_run_id / run_metadata are provenance from an upstream Conductor run; they
    are not PII, so they are stored plaintext (keeping them queryable/filterable)."""
    return (
        encrypt_field(FERNET, title), category, severity,
        body.get("source") or None,
        encrypt_field(FERNET, body.get("source_ip") or None),
        encrypt_field(FERNET, body.get("description") or None),
        body.get("workflow_run_id") or None,
        body.get("run_metadata") or None,
    )


def _insert_alert(body: dict, title: str, category: str, severity: str) -> dict:
    """Persist one alert to the DB, store its embedding, broadcast SSE, return the row.

    Called by both POST /api/alerts (after key check) and the Kafka consumer, so
    the DB insert, encryption, embedding, and SSE logic live in exactly one place.
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (title, category, severity, source, source_ip, description,
                                workflow_run_id, run_metadata, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'open')
            RETURNING *
            """,
            _ingest_values(body, title, category, severity),
        )
        created = cur.fetchone()

    # Store semantic embedding (best-effort — ingest succeeds even without pgvector)
    embed_text = " ".join(filter(None, [title, body.get("description"), category]))
    vec_str = _embed_text(embed_text)
    if vec_str:
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO alert_embeddings (alert_id, embedding) "
                    "VALUES (%s, %s::vector) "
                    "ON CONFLICT (alert_id) DO UPDATE SET embedding = EXCLUDED.embedding",
                    (created["id"], vec_str),
                )
        except Exception as exc:
            logger.warning(
                "alert_embeddings insert failed for alert_id=%s: %s",
                created["id"], exc,
            )

    row = serialize(decrypt_alert(dict(created)))
    _sse_publish({
        "type": "new_alert",
        "alert_id": row["id"],
        "severity": row["severity"],
        "status": row["status"],
    })
    return row


def _kafka_ingest(body: dict) -> None:
    """Validate and store one Kafka-sourced alert body.

    Raises ValueError on invalid payloads so the consumer can log and skip.
    """
    title    = (body.get("title") or "").strip()
    category = (body.get("category") or "").strip()
    severity = (body.get("severity") or "").strip().upper()
    if not title or not category or severity not in SEVERITY_RANK:
        raise ValueError(
            f"invalid alert body: title={title!r} category={category!r} severity={severity!r}"
        )
    _insert_alert(body, title, category, severity)


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
    row = _insert_alert(body, title, category, severity)
    return jsonify(row), 201


@app.route("/api/alerts/<int:alert_id>/similar")
@login_required
def api_similar_alerts(alert_id):
    """Return the top-5 alerts most semantically similar to alert_id by cosine distance."""
    if not _embeddings_available():
        return jsonify({
            "error": "embeddings_unavailable",
            "detail": "fastembed model failed to load at startup; restart the server to retry",
        }), 503
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.id, a.title, a.category, a.severity, a.status, a.created_at,
                       round((1 - (ref.embedding <=> cmp.embedding))::numeric, 3) AS similarity
                FROM   alert_embeddings ref
                JOIN   alert_embeddings cmp ON cmp.alert_id != ref.alert_id
                JOIN   alerts           a   ON a.id = cmp.alert_id
                WHERE  ref.alert_id = %s
                ORDER  BY ref.embedding <=> cmp.embedding
                LIMIT  5
                """,
                (alert_id,),
            )
            rows = cur.fetchall()
    except Exception:
        return jsonify([])
    return jsonify([
        {
            "id":         r["id"],
            "title":      decrypt_field(FERNET, r["title"]),
            "category":   r["category"],
            "severity":   r["severity"],
            "status":     r["status"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "similarity": float(r["similarity"]),
        }
        for r in rows
    ])


@app.route("/api/alerts/<int:alert_id>/classify", methods=["POST"])
@login_required
@require_role("analyst", "admin")
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
        # Audit trail — same transaction as the alert update (atomic).
        cur.execute(
            """
            INSERT INTO audit_log
                (alert_id, user_id, username, action, from_status, to_status)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                alert_id,
                int(current_user.id),
                current_user.username,
                action,
                alert["status"],
                new_status,
            ),
        )

    result = serialize(updated)
    _sse_publish({
        "type": "status_change",
        "alert_id": alert_id,
        "severity": updated.get("severity"),
        "status": new_status,
    })
    return jsonify(result)


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


# --------------------------------------------------------------------------- #
# Audit trail routes
# --------------------------------------------------------------------------- #
@app.route("/api/alerts/<int:alert_id>/audit")
@login_required
def api_alert_audit(alert_id):
    """Return the audit history for a single alert as JSON."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, alert_id, user_id, username, action,
                   from_status, to_status, note, created_at
            FROM audit_log
            WHERE alert_id = %s
            ORDER BY created_at ASC
            """,
            (alert_id,),
        )
        rows = cur.fetchall()
    result = []
    for r in rows:
        row = dict(r)
        row["note"] = decrypt_field(FERNET, row["note"])
        result.append(serialize(row))
    return jsonify(result)


@app.route("/audit")
@login_required
@require_role("admin")
def audit_log_page():
    """Paginated audit log view, admin-only."""
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    offset = (page - 1) * per_page
    search = (request.args.get("q") or "").strip()

    with get_conn() as conn, conn.cursor() as cur:
        if search:
            cur.execute(
                """
                SELECT al.id, al.alert_id, al.username, al.action,
                       al.from_status, al.to_status, al.created_at, al.note
                FROM audit_log al
                WHERE al.username ILIKE %s OR al.action ILIKE %s
                ORDER BY al.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (f"%{search}%", f"%{search}%", per_page, offset),
            )
        else:
            cur.execute(
                """
                SELECT al.id, al.alert_id, al.username, al.action,
                       al.from_status, al.to_status, al.created_at, al.note
                FROM audit_log al
                ORDER BY al.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (per_page, offset),
            )
        rows = cur.fetchall()
        cur.execute("SELECT count(*) AS c FROM audit_log")
        total = cur.fetchone()["c"]

    entries = []
    for r in rows:
        row = dict(r)
        row["note"] = decrypt_field(FERNET, row["note"])
        entries.append(serialize(row))

    return render_template(
        "audit.html",
        entries=entries,
        page=page,
        per_page=per_page,
        total=total,
        search=search,
    )


@app.route("/api/alerts/<int:alert_id>/notes", methods=["POST"])
@login_required
@require_role("analyst", "admin")
def api_add_note(alert_id):
    """Add a case note to an alert. Stored encrypted, logged in audit_log."""
    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip()
    if not note:
        abort(400, description="note is required")

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM alerts WHERE id = %s", (alert_id,))
        alert = cur.fetchone()
        if alert is None:
            abort(404, description="alert not found")

        cur.execute(
            """
            INSERT INTO audit_log
                (alert_id, user_id, username, action, from_status, to_status, note)
            VALUES (%s, %s, %s, 'note_added', %s, %s, %s)
            RETURNING id, created_at
            """,
            (
                alert_id,
                int(current_user.id),
                current_user.username,
                alert["status"],
                alert["status"],
                encrypt_field(FERNET, note),
            ),
        )
        row = cur.fetchone()

    return jsonify({"id": row["id"], "created_at": row["created_at"].isoformat()}), 201


# --------------------------------------------------------------------------- #
# Conductor human-approval gate
# --------------------------------------------------------------------------- #
# Task reference name of the WAIT task defined in conductor_orchestrated.json.
# Completing it by this ref name releases a CRITICAL-severity workflow run.
_CONDUCTOR_APPROVAL_TASK_REF = "approval_wait_ref"


@app.route("/api/alerts/<workflow_run_id>/approve", methods=["POST"])
@login_required
def api_approve_workflow(workflow_run_id):
    """Release the human-approval WAIT gate for a CRITICAL-incident workflow run.

    Calls the Conductor Task Update API to mark the WAIT task (approval_wait_ref)
    as COMPLETED, which lets the workflow proceed to push_to_dashboard. Requires
    analyst login; returns 503 when Conductor is not configured in the environment.

    POST body (JSON, optional):
        { "note": "<analyst note about the approval decision>" }

    Returns 200 with the workflow_run_id and approving analyst on success.
    """
    try:
        from conductor.client.configuration.configuration import Configuration
        from conductor.client.orkes.orkes_task_client import OrkesTaskClient
    except ImportError:
        return jsonify({"error": "conductor SDK not installed"}), 503

    if not os.environ.get("CONDUCTOR_SERVER_URL"):
        return jsonify({"error": "CONDUCTOR_SERVER_URL not configured"}), 503

    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip()

    try:
        task_client = OrkesTaskClient(Configuration())
        task_client.update_task_sync(
            workflow_id=workflow_run_id,
            task_ref_name=_CONDUCTOR_APPROVAL_TASK_REF,
            status="COMPLETED",
            output={
                "approved_by": current_user.username,
                "note": note,
            },
        )
    except Exception as exc:
        logger.warning(
            "Conductor approval failed for workflow %s: %s", workflow_run_id, exc
        )
        return jsonify({"error": f"conductor error: {type(exc).__name__}"}), 502

    return jsonify({
        "workflow_run_id": workflow_run_id,
        "approved_by": current_user.username,
        "status": "released",
    })


# --------------------------------------------------------------------------- #
# ATT&CK Navigator layer export
# --------------------------------------------------------------------------- #
@app.route("/api/navigator-layer")
@login_required
def api_navigator_layer():
    """Return the current alert corpus as an ATT&CK Navigator 4.9 layer JSON.

    Groups alerts by category → MITRE technique, scoring each entry by the
    highest observed severity. The JSON can be imported directly at
    https://mitre-attack.github.io/attack-navigator/.
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT category, severity, count(*) AS c "
            "FROM alerts GROUP BY category, severity"
        )
        rows = cur.fetchall()

    techniques: dict[str, dict] = {}
    total = 0
    for row in rows:
        cat   = row["category"]
        sev   = row["severity"]
        count = row["c"]
        total += count
        tid   = _CATEGORY_MITRE.get(cat)
        if not tid:
            continue
        score = _NAVIGATOR_SCORE.get(sev, 25)
        if tid not in techniques or score > techniques[tid]["score"]:
            techniques[tid] = {
                "techniqueID": tid,
                "score":       score,
                "color":       "",
                "comment":     f"{cat}: {count} alert(s), {sev}",
                "enabled":     True,
            }

    layer = {
        "name": "SOC Dashboard Alert Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"ATT&CK coverage derived from {total} SOC alert(s).",
        "techniques": list(techniques.values()),
        "gradient": {
            "colors":   ["#ffd700", "#ff6600", "#cc0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "CRITICAL (100)", "color": "#cc0000"},
            {"label": "HIGH (75)",      "color": "#ff6600"},
            {"label": "MEDIUM (50)",    "color": "#ffd700"},
            {"label": "LOW (25)",       "color": "#33cc66"},
        ],
        "showTacticRowBackground":      False,
        "selectTechniquesAcrossTactics": True,
    }
    return jsonify(layer)


# --------------------------------------------------------------------------- #
# Server-Sent Events
# --------------------------------------------------------------------------- #
@app.route("/api/stream")
@login_required
def api_stream():
    """SSE endpoint for live queue updates.

    When Redis is configured, subscribes to _REDIS_SSE_CHANNEL so events
    published by any worker process reach every connected client. Falls back
    to the in-process Queue for single-worker deployments.
    """
    def generate():
        if _REDIS_CLIENT is not None:
            ps = _REDIS_CLIENT.pubsub()
            ps.subscribe(_REDIS_SSE_CHANNEL)
            try:
                while True:
                    msg = ps.get_message(ignore_subscribe_messages=True, timeout=30)
                    if msg and msg["type"] == "message":
                        yield f"data: {msg['data'].decode()}\n\n"
                    else:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                pass
            finally:
                try:
                    ps.unsubscribe(_REDIS_SSE_CHANNEL)
                    ps.close()
                except Exception:
                    pass
        else:
            q = _sse_subscribe()
            try:
                while True:
                    try:
                        event = q.get(timeout=30)
                        yield f"data: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                pass
            finally:
                _sse_unsubscribe(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
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


# Start the Kafka alert consumer when KAFKA_BROKER is configured.
# Silently absent when the env var is unset — REST ingest continues unchanged.
_KAFKA_BROKER = os.environ.get("KAFKA_BROKER")
if _KAFKA_BROKER:
    try:
        from kafka.consumer import KafkaAlertConsumer as _KafkaAlertConsumer
        _kafka_consumer = _KafkaAlertConsumer(_KAFKA_BROKER, ingest_fn=_kafka_ingest)
        _kafka_consumer.start()
        print(f"[+] Kafka consumer started (broker={_KAFKA_BROKER})")
    except ImportError:
        print("[!] confluent-kafka not installed; Kafka consumer not started "
              "(pip install confluent-kafka)")


if __name__ == "__main__":
    # Debug and bind address come from the environment so production never runs
    # the Werkzeug debugger or binds every interface by accident. Defaults are
    # safe: debugger off, loopback only. Set FLASK_DEBUG=1 for local dev and
    # HOST=0.0.0.0 when you genuinely need to expose the port (e.g. in Docker).
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes", "on")
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("PORT", 8000)), debug=debug)
