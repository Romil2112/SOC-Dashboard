"""Unit tests for field-level encryption (no database required)."""
import crypto


def test_encrypt_decrypt_round_trip(monkeypatch):
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "unit-test-key")
    fernet = crypto.get_fernet()
    assert fernet is not None

    plaintext = "10.1.2.3 / admin"
    token = crypto.encrypt_field(fernet, plaintext)
    assert token != plaintext  # actually encrypted
    assert crypto.decrypt_field(fernet, token) == plaintext


def test_none_passes_through(monkeypatch):
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "unit-test-key")
    fernet = crypto.get_fernet()
    assert crypto.encrypt_field(fernet, None) is None
    assert crypto.decrypt_field(fernet, None) is None


def test_encryption_disabled_passthrough(monkeypatch):
    monkeypatch.delenv("DB_ENCRYPTION_KEY", raising=False)
    fernet = crypto.get_fernet()
    assert fernet is None
    # With no key, values pass through unchanged in both directions.
    assert crypto.encrypt_field(fernet, "secret") == "secret"
    assert crypto.decrypt_field(fernet, "secret") == "secret"


def test_decrypt_of_legacy_plaintext_is_graceful(monkeypatch):
    # A value stored before encryption was enabled is not a valid token;
    # decrypt_field should return it unchanged rather than raising.
    monkeypatch.setenv("DB_ENCRYPTION_KEY", "unit-test-key")
    fernet = crypto.get_fernet()
    assert crypto.decrypt_field(fernet, "plain-legacy-value") == "plain-legacy-value"
