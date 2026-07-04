"""Tests for the user-management CLI (manage.py)."""
import os

import bcrypt
import psycopg2

import manage


def _fetch_user(username):
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT role, password_hash FROM users WHERE username = %s", (username,)
        )
        row = cur.fetchone()
    conn.close()
    return row


def test_create_user_success(provisioned_db):
    assert manage.create_user("newanalyst", "pw-123456", "analyst") == 0
    role, _ = _fetch_user("newanalyst")
    assert role == "analyst"


def test_create_user_admin_role(provisioned_db):
    assert manage.create_user("bossadmin", "pw-123456", "admin") == 0
    assert _fetch_user("bossadmin")[0] == "admin"


def test_password_is_bcrypt_hashed_not_plaintext(provisioned_db):
    manage.create_user("hashcheck", "s3cret-pw", "analyst")
    _, pw_hash = _fetch_user("hashcheck")
    assert pw_hash.startswith("$2b$")
    assert pw_hash != "s3cret-pw"
    assert bcrypt.checkpw(b"s3cret-pw", pw_hash.encode("ascii"))


def test_duplicate_user_returns_1(provisioned_db):
    assert manage.create_user("dupe", "pw-123456", "analyst") == 0
    assert manage.create_user("dupe", "pw-123456", "analyst") == 1  # already exists


def test_main_dispatches_create_user(provisioned_db):
    rc = manage.main(["create-user", "viacli", "pw-123456", "--role", "admin"])
    assert rc == 0
    assert _fetch_user("viacli")[0] == "admin"


def test_connection_failure_returns_2(monkeypatch):
    # Point at a port nothing listens on so connect() fails fast, exercising the
    # graceful "could not connect" path (exit code 2).
    monkeypatch.setattr(
        manage, "DATABASE_URL", "postgresql://localhost:1/nonexistent"
    )
    assert manage.create_user("whoever", "pw", "analyst") == 2
