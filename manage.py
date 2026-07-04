"""User-management CLI for the SOC dashboard.

Accounts are created here only — there is no self-registration in the app.

Usage:
    python manage.py create-user <username> <password> [--role analyst|admin]

Connects via DATABASE_URL. Passwords are hashed with bcrypt (12 rounds) and
never stored in plaintext.
"""
import argparse
import os
import sys

import bcrypt
import psycopg2
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://localhost/soc_dashboard"
)

BCRYPT_ROUNDS = 12


def create_user(username, password, role):
    """Create an account. Returns a process exit code (0 = success)."""
    pw_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")
    try:
        conn = psycopg2.connect(DATABASE_URL)
    except psycopg2.Error as exc:
        print(f"error: could not connect to database: {exc}", file=sys.stderr)
        return 2
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                print(f"error: user '{username}' already exists", file=sys.stderr)
                return 1
            cur.execute(
                "INSERT INTO users (username, password_hash, role) "
                "VALUES (%s, %s, %s)",
                (username, pw_hash, role),
            )
        print(f"created {role} '{username}'")
        return 0
    except psycopg2.Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        conn.close()


def main(argv=None):
    """Parse argv and dispatch the create-user subcommand; return an exit code."""
    parser = argparse.ArgumentParser(description="SOC dashboard user management")
    sub = parser.add_subparsers(dest="command", required=True)

    cu = sub.add_parser("create-user", help="Create an analyst/admin account")
    cu.add_argument("username")
    cu.add_argument("password")
    cu.add_argument("--role", choices=["analyst", "admin"], default="analyst")

    args = parser.parse_args(argv)
    if args.command == "create-user":
        return create_user(args.username, args.password, args.role)
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
