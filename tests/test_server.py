"""Tests for the server CLI and MCP entrypoints."""

from __future__ import annotations

import json

import pytest

from agent_authenticator import audit, vault
from agent_authenticator import server


@pytest.fixture(autouse=True)
def tmp_vault(tmp_path, monkeypatch):
    vault_file = tmp_path / "vault.json"
    key_file = tmp_path / ".key"
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(vault, "VAULT_PATH", vault_file)
    monkeypatch.setattr(vault, "KEY_PATH", key_file)
    monkeypatch.setattr(audit, "AUDIT_PATH", audit_file)
    return vault_file


def test_full_workflow(tmp_vault):
    vault.add_from_uri(
        "x-stella",
        "otpauth://totp/X.com:stella@forge.se?secret=JBSWY3DPEHPK3PXP&issuer=X.com",
    )
    assert vault.list_accounts() == ["x-stella"]
    info = vault.get_account_info("x-stella")
    assert info["issuer"] == "X.com"
    assert "secret" not in info
    code = vault.generate_totp("x-stella")
    assert len(code) == 6
    vault.remove_account("x-stella")
    assert vault.list_accounts() == []


def test_cli_doctor_json(capsys):
    exit_code = server.main(["doctor", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["account_count"] == 0
    assert payload["vault_path"].endswith("vault.json")


def test_remote_http_requires_explicit_flag():
    with pytest.raises(SystemExit, match="--allow-remote-http"):
        server.main(["serve", "--transport", "http", "--host", "0.0.0.0"])


def test_legacy_transport_flags_are_still_supported(monkeypatch):
    calls = []

    def fake_run(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(server.mcp, "run", fake_run)
    exit_code = server.main(["--transport", "stdio"])
    assert exit_code == 0
    assert calls == [{"transport": "stdio", "show_banner": False}]
