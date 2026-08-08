"""Seed the SOC dashboard with 50 realistic alerts and analyst actions.

Distributions enforced:
  category: 12 brute_force, 10 malware, 10 phishing, 10 port_scan, 8 anomaly
  severity: 8 CRITICAL, 15 HIGH, 17 MEDIUM, 10 LOW
  status:   30 closed (with analyst_actions), 20 open

Demo-data targets (healthy, well-tuned SOC):
  SLA breach rate  ~8–12%  (open alerts are recent; closed are fast responses)
  escalation rate  ~7–10%  (most alerts closed as TP or FP; few escalated)
"""
import os
import random
from datetime import datetime, timedelta, timezone

import psycopg2
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://localhost/soc_dashboard"
)

random.seed(1337)  # reproducible seed data

ANALYSTS = ["alice", "bob", "charlie"]

# Action -> resulting alert status for closed alerts.
ACTION_TO_STATUS = {
    "classify_tp": "true_positive",
    "classify_fp": "false_positive",
    "escalate": "escalated",
}

# Detecting sensor/tool per category — the "source" dimension analysts filter on.
SOURCES = {
    "brute_force": "Auth Logs",
    "malware":     "EDR",
    "phishing":    "Email Gateway",
    "port_scan":   "Firewall/IDS",
    "anomaly":     "SIEM/UEBA",
}

# Realistic title/description templates keyed by category.
TEMPLATES = {
    "brute_force": [
        ("SSH brute-force against {host}",
         "{n} failed SSH logins for user {user} from {ip} within 2 minutes."),
        ("RDP password spray detected",
         "Multiple failed RDP authentications from {ip} targeting {n} accounts."),
        ("Failed login burst on VPN gateway",
         "{n} failed VPN auth attempts from {ip} for account {user}."),
        ("Repeated 401s on admin portal",
         "Login endpoint hit {n} times with bad credentials from {ip}."),
        ("SMB authentication failures",
         "Account lockout triggered after {n} failed SMB logons from {ip}."),
    ],
    "malware": [
        ("Trojan.Emotet detected on {host}",
         "EDR quarantined Emotet payload dropped by {ip}; persistence attempted."),
        ("Ransomware behavior on endpoint",
         "Mass file rename + shadow-copy deletion observed on {host}."),
        ("Cobalt Strike beacon to {ip}",
         "Periodic beaconing to known C2 {ip} from {host}."),
        ("Suspicious PowerShell encoded command",
         "Base64 PowerShell spawned by Office process on {host}."),
        ("Known malware hash executed",
         "Process on {host} matched threat-intel hash; outbound to {ip}."),
    ],
    "phishing": [
        ("Credential-harvesting email reported",
         "User reported phishing email with link to fake O365 login from {ip}."),
        ("Spoofed CEO wire-transfer request",
         "BEC email impersonating executive sent to finance; reply-to {ip}."),
        ("Malicious attachment delivered",
         "Macro-enabled doc detected in inbound mail from {ip}."),
        ("Phishing link clicked by {user}",
         "Proxy logged {user} visiting credential-phish domain hosted at {ip}."),
        ("OAuth consent phishing attempt",
         "Suspicious app consent grant requested for {user} via {ip}."),
    ],
    "port_scan": [
        ("Horizontal port scan from {ip}",
         "{ip} probed TCP/22,80,443,3389 across {n} internal hosts."),
        ("Nmap SYN scan detected",
         "Stealth SYN scan from {ip} hit {n} ports on {host}."),
        ("External recon on perimeter",
         "Firewall logged {n} dropped probes from {ip} in 60s."),
        ("Vertical scan against {host}",
         "{ip} swept {n} ports on a single host {host}."),
        ("UDP service enumeration",
         "{ip} enumerated UDP services across {n} hosts."),
    ],
    "anomaly": [
        ("Impossible travel for {user}",
         "{user} signed in from two countries within 20 minutes (last IP {ip})."),
        ("Off-hours data exfiltration",
         "{host} uploaded {n} MB to {ip} at 03:00 local time."),
        ("Privilege escalation anomaly",
         "{user} added to Domain Admins outside change window."),
        ("Unusual DNS volume",
         "{host} issued {n} DNS queries to {ip} (possible tunneling)."),
        ("New admin login geo-anomaly",
         "First-ever admin login for {user} from {ip}."),
    ],
}

HOSTS = ["WIN-DC01", "FIN-WS07", "HR-LT12", "WEB-PROD-03", "DB-CORE-01",
         "ENG-MAC22", "VPN-GW01", "SRV-APP09", "MKT-WS18", "OPS-JUMP02"]
USERS = ["jdoe", "asmith", "mpatel", "rking", "lchen", "twong", "svc_backup",
         "admin", "kbrown", "ngarcia"]


def rand_public_ip():
    """A plausible external/public IPv4 (avoids private ranges)."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def rand_internal_ip():
    """A random RFC1918 internal IPv4 in the 10.x.x.x block."""
    return f"10.{random.randint(0,40)}.{random.randint(0,255)}.{random.randint(1,254)}"


def build_alerts():
    """Return a list of 50 alert dicts honoring the required distributions."""
    categories = (
        ["brute_force"] * 12
        + ["malware"] * 10
        + ["phishing"] * 10
        + ["port_scan"] * 10
        + ["anomaly"] * 8
    )
    severities = (
        ["CRITICAL"] * 8 + ["HIGH"] * 15 + ["MEDIUM"] * 17 + ["LOW"] * 10
    )
    random.shuffle(categories)
    random.shuffle(severities)

    now = datetime.now(timezone.utc)
    alerts = []
    # The category and severity lists are both length 50 by construction;
    # strict=True makes that invariant explicit and fails loudly if it drifts.
    for category, severity in zip(categories, severities, strict=True):
        title_tpl, desc_tpl = random.choice(TEMPLATES[category])
        fields = {
            "host": random.choice(HOSTS),
            "user": random.choice(USERS),
            "ip": rand_public_ip() if category in ("brute_force", "port_scan",
                                                    "phishing", "malware")
            else random.choice([rand_public_ip(), rand_internal_ip()]),
            "n": random.randint(8, 240),
        }
        # External-facing source IP for the alert row.
        source_ip = fields["ip"]
        created_at = now - timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        alerts.append(
            {
                "title": title_tpl.format(**fields),
                "category": category,
                "severity": severity,
                "source": SOURCES[category],
                "source_ip": source_ip,
                "description": desc_tpl.format(**fields),
                "created_at": created_at,
            }
        )
    return alerts


# Response-time ranges (seconds) that keep closed alerts well within SLA.
# SLA thresholds: CRITICAL=15m, HIGH=1hr, MEDIUM=4hr, LOW=24hr.
_RESPONSE_RANGE = {
    "CRITICAL": (120,  600),    # 2–10 min  (SLA 15 min)
    "HIGH":     (600, 2400),    # 10–40 min (SLA 60 min)
    "MEDIUM":   (1800, 9000),   # 30–150 min (SLA 4 hr)
    "LOW":      (3600, 36000),  # 1–10 hr   (SLA 24 hr)
}

# Weighted action pool: ~7% escalation, rest split TP/FP.
_ACTION_POOL = (
    ["classify_tp"] * 11
    + ["classify_fp"] * 7
    + ["escalate"] * 2
)


def main():
    """Truncate and re-seed the database with 50 demo alerts (30 already closed).

    Targets a healthy SOC appearance:
      SLA breach rate  ~8–12%  — open alerts are fresh (< 35 min old);
                                  closed alerts have fast, in-SLA response times.
      escalation rate  ~7–10%  — weighted action pool, not uniform random.
    """
    alerts = build_alerts()
    now = datetime.now(timezone.utc)

    # Pick 30 of the 50 to be already closed (triaged).
    closed_idx = set(random.sample(range(len(alerts)), 30))

    # Reassign created_at for open alerts based on severity:
    #   CRITICAL — 18–30 min ago: intentionally past the 15-min SLA so the
    #              dashboard shows the tool actively catching live breaches.
    #   HIGH     — 10–45 min ago: within the 60-min SLA.
    #   MEDIUM   — 20–90 min ago: within the 4-hr SLA.
    #   LOW      — 30–180 min ago: well within the 24-hr SLA.
    _open_age = {
        "CRITICAL": (18, 30),    # SLA 15 min  — all breach, showing live monitoring
        "HIGH":     (30, 85),    # SLA 60 min  — upper half breach (~40% of open HIGH)
        "MEDIUM":   (20, 90),    # SLA 240 min — none breach
        "LOW":      (30, 180),   # SLA 1440 min — none breach
    }
    for i, a in enumerate(alerts):
        if i not in closed_idx:
            lo, hi = _open_age.get(a["severity"], (10, 60))
            a["created_at"] = now - timedelta(minutes=random.randint(lo, hi))

    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            # Idempotent re-seed.
            cur.execute("TRUNCATE analyst_actions, alerts RESTART IDENTITY CASCADE")

            for i, a in enumerate(alerts):
                if i in closed_idx:
                    action = random.choice(_ACTION_POOL)
                    status = ACTION_TO_STATUS[action]
                    analyst = random.choice(ANALYSTS)
                else:
                    action = status = analyst = None
                    status = "open"

                cur.execute(
                    """
                    INSERT INTO alerts
                        (title, category, severity, source, source_ip, description,
                         created_at, status, assigned_to)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                    """,
                    (
                        a["title"], a["category"], a["severity"], a["source"],
                        a["source_ip"], a["description"], a["created_at"],
                        status, analyst,
                    ),
                )
                alert_id = cur.fetchone()[0]

                if i in closed_idx:
                    lo, hi = _RESPONSE_RANGE.get(a["severity"], (300, 3600))
                    response_time = random.randint(lo, hi)
                    acted_at = a["created_at"] + timedelta(seconds=response_time)
                    cur.execute(
                        """
                        INSERT INTO analyst_actions
                            (alert_id, analyst_name, action, acted_at,
                             response_time_seconds)
                        VALUES (%s,%s,%s,%s,%s)
                        """,
                        (alert_id, analyst, action, acted_at, response_time),
                    )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    closed = len(closed_idx)
    print(f"Seeded {len(alerts)} alerts ({closed} closed, {len(alerts)-closed} open).")


if __name__ == "__main__":
    main()
