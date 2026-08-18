"""User-management CLI for the SOC dashboard.

Accounts are created here only — there is no self-registration in the app.

Usage:
    python manage.py create-user <username> <password> [--role analyst|admin]

Always writes to every reachable database (local brew postgres via Unix socket
and Docker postgres via TCP) so credentials work regardless of how the app is
started.
"""
import argparse
import os
import subprocess
import sys

import bcrypt
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Primary URL from env (defaults to local brew postgres via Unix socket).
_PRIMARY_URL = os.environ.get(
    "DATABASE_URL", "postgresql://localhost/soc_dashboard"
)

# Docker postgres is always attempted on TCP regardless of DATABASE_URL.
_DOCKER_URL = "postgresql://soc:soc@localhost:5432/soc_dashboard"

BCRYPT_ROUNDS = 12


_DOCKER_CONTAINER = "soc-dashboard-web-1"


def _create_in_local(username, pw_hash, role):
    """Write to local brew postgres via Unix socket."""
    try:
        conn = psycopg2.connect(_PRIMARY_URL, connect_timeout=3)
    except psycopg2.OperationalError as exc:
        return False, f"unreachable ({exc})"
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                return False, f"user '{username}' already exists"
            cur.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, %s)",
                (username, pw_hash, role),
            )
        return True, f"created {role} '{username}'"
    except psycopg2.Error as exc:
        return False, str(exc)
    finally:
        conn.close()


def _create_in_docker(username, password, role):
    """Write to Docker postgres by exec-ing into the web container."""
    probe = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", _DOCKER_CONTAINER],
        capture_output=True, text=True,
    )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return False, "container not running"
    result = subprocess.run(
        ["docker", "exec", _DOCKER_CONTAINER,
         "python", "manage.py", "create-user", username, password, "--role", role],
        capture_output=True, text=True,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        return True, output
    return False, output


def create_user(username, password, role):
    """Create the account in every reachable database. Returns 0 if at least one succeeded."""
    pw_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")

    any_ok = False

    ok, msg = _create_in_local(username, pw_hash, role)
    print(f"[{'ok' if ok else 'skip'}] local-db: {msg}")
    any_ok = any_ok or ok

    ok, msg = _create_in_docker(username, password, role)
    print(f"[{'ok' if ok else 'skip'}] docker-db: {msg}")
    any_ok = any_ok or ok

    return 0 if any_ok else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="SOC dashboard user management")
    sub = parser.add_subparsers(dest="command", required=True)

    cu = sub.add_parser("create-user", help="Create an analyst/admin account")
    cu.add_argument("username")
    cu.add_argument("password")
    cu.add_argument("--role", choices=["viewer", "analyst", "admin"], default="analyst")

    args = parser.parse_args(argv)
    if args.command == "create-user":
        return create_user(args.username, args.password, args.role)
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
