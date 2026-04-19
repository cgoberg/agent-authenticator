"""Tests for the encrypted vault module."""

from __future__ import annotations

import json
import threading
import time as time_module

import pytest

from agent_authenticator import audit, vault


@pytest.fixture(autouse=True)
def tmp_vault(tmp_path, monkeypatch):
    vault_file = tmp_path / "vault.json"
    key_file = tmp_path / ".key"
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(vault, "VAULT_PATH", vault_file)
    monkeypatch.setattr(vault, "KEY_PATH", key_file)
    monkeypatch.setattr(audit, "AUDIT_PATH", audit_file)
    return vault_file


def test_add_and_generate(tmp_vault):
    vault.add_account("test-acct", "JBSWY3DPEHPK3PXP", issuer="TestApp")
    code = vault.generate_totp("test-acct")
    assert len(code) == 6
    assert code.isdigit()


def test_list_accounts(tmp_vault):
    vault.add_account("alpha", "JBSWY3DPEHPK3PXP")
    vault.add_account("beta", "JBSWY3DPEHPK3PXP")
    assert vault.list_accounts() == ["alpha", "beta"]


def test_get_account_info(tmp_vault):
    vault.add_account("test-acct", "JBSWY3DPEHPK3PXP", issuer="X.com")
    info = vault.get_account_info("test-acct")
    assert info["issuer"] == "X.com"
    assert info["digits"] == 6
    assert "secret" not in info


def test_add_from_uri(tmp_vault):
    uri = "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    vault.add_from_uri("github", uri)
    code = vault.generate_totp("github")
    assert len(code) == 6


def test_remove_account(tmp_vault):
    vault.add_account("to-remove", "JBSWY3DPEHPK3PXP")
    vault.remove_account("to-remove")
    assert "to-remove" not in vault.list_accounts()


def test_generate_missing_account_raises(tmp_vault):
    with pytest.raises(ValueError, match="not found"):
        vault.generate_totp("nonexistent")


def test_vault_is_encrypted_at_rest(tmp_vault):
    secret = "JBSWY3DPEHPK3PXP"
    vault.add_account("enc-test", secret, issuer="Test")
    with open(tmp_vault, encoding="utf-8") as handle:
        raw = json.load(handle)
    stored = raw["accounts"]["enc-test"]["secret"]
    assert stored != secret
    assert secret not in stored


def test_file_locking_prevents_corruption(tmp_vault):
    results = []
    errors = []

    def worker(i):
        try:
            vault.add_account(f"concurrent-{i}", "JBSWY3DPEHPK3PXP", issuer=f"Test{i}")
            time_module.sleep(0.01)
            code = vault.generate_totp(f"concurrent-{i}")
            results.append(code)
        except Exception as exc:  # pragma: no cover - test collects the errors
            errors.append(str(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == [], f"Errors during concurrent access: {errors}"
    assert len(results) == 10
    assert all(len(code) == 6 and code.isdigit() for code in results)
    accounts = vault.list_accounts()
    assert len([name for name in accounts if name.startswith("concurrent-")]) == 10


def test_generate_key_returns_valid_fernet_key():
    key = vault.generate_key()
    assert isinstance(key, str)
    assert len(key) > 20
