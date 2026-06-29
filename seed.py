"""Seed the SOC dashboard with 50 realistic alerts and analyst actions.

Distributions enforced:
  category: 12 brute_force, 10 malware, 10 phishing, 10 port_scan, 8 anomaly
  severity: 8 CRITICAL, 15 HIGH, 17 MEDIUM, 10 LOW
  status:   30 closed (with analyst_actions), 20 open
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
    for category, severity in zip(categories, severities):
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


def main():
    alerts = build_alerts()

    # Pick 30 of the 50 to be already closed (triaged).
    closed_idx = set(random.sample(range(len(alerts)), 30))

    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            # Idempotent re-seed.
            cur.execute("TRUNCATE analyst_actions, alerts RESTART IDENTITY CASCADE")

            for i, a in enumerate(alerts):
                if i in closed_idx:
                    action = random.choice(list(ACTION_TO_STATUS.keys()))
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
                    response_time = random.randint(60, 3600)
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
