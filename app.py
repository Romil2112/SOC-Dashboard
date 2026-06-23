"""SOC Analyst Dashboard — Flask + psycopg2 (no ORM)."""
import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template, request

load_dotenv()

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://localhost/soc_dashboard"
)

app = Flask(__name__)

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


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/analyst")
def analyst():
    return render_template("analyst.html")


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/alerts")
def api_open_alerts():
    """Open alerts only, sorted CRITICAL -> LOW then newest first."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM alerts
            WHERE status = 'open'
            ORDER BY CASE severity
                         WHEN 'CRITICAL' THEN 1
                         WHEN 'HIGH'     THEN 2
                         WHEN 'MEDIUM'   THEN 3
                         WHEN 'LOW'      THEN 4
                         ELSE 5
                     END,
                     created_at DESC
            """
        )
        rows = cur.fetchall()
    return jsonify([serialize(r) for r in rows])


@app.route("/api/alerts/all")
def api_all_alerts():
    """Every alert, sorted CRITICAL -> LOW then newest first."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM alerts
            ORDER BY CASE severity
                         WHEN 'CRITICAL' THEN 1
                         WHEN 'HIGH'     THEN 2
                         WHEN 'MEDIUM'   THEN 3
                         WHEN 'LOW'      THEN 4
                         ELSE 5
                     END,
                     created_at DESC
            """
        )
        rows = cur.fetchall()
    return jsonify([serialize(r) for r in rows])


@app.route("/api/alerts", methods=["POST"])
def api_ingest_alert():
    """Ingest a new alert into the open queue.

    This is the entry point that lets an upstream detector (e.g. log-analyzer)
    push real incidents into the dashboard instead of relying on seed data.
    """
    body = request.get_json(silent=True) or {}
    title    = (body.get("title") or "").strip()
    category = (body.get("category") or "").strip()
    severity = (body.get("severity") or "").strip().upper()

    if not title or not category:
        abort(400, description="title and category are required")
    if severity not in SEVERITY_RANK:
        abort(400, description="severity must be CRITICAL, HIGH, MEDIUM or LOW")

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (title, category, severity, source_ip, description, status)
            VALUES (%s, %s, %s, %s, %s, 'open')
            RETURNING *
            """,
            (title, category, severity,
             body.get("source_ip") or None, body.get("description") or None),
        )
        created = cur.fetchone()

    return jsonify(serialize(created)), 201


@app.route("/api/alerts/<int:alert_id>/classify", methods=["POST"])
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
        updated = cur.fetchone()

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

        # SLA inputs: each alert's severity, age, and (earliest) triage response time.
        cur.execute(
            """
            SELECT a.severity,
                   a.created_at,
                   (SELECT min(aa.response_time_seconds)
                      FROM analyst_actions aa
                     WHERE aa.alert_id = a.id) AS resp
            FROM alerts a
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
            "mttr_by_analyst": mttr_by_analyst,
            "sla": sla,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True)
