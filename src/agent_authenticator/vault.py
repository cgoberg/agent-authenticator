"""Encrypted TOTP vault for Forge Nord's agent-authenticator.

Secrets are encrypted at rest with Fernet and only decrypted long enough to
generate a TOTP code. Vault mutations are performed under a single file lock so
concurrent writers do not clobber each other.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Callable, TypeVar

from cryptography.fernet import Fernet
from filelock import FileLock
import pyotp

VAULT_PATH = Path(
    os.environ.get(
        "AGENT_AUTH_VAULT",
        Path.home() / ".agent-authenticator" / "vault.json",
    )
)
KEY_PATH = Path(
    os.environ.get(
        "AGENT_AUTH_KEY_FILE",
        Path.home() / ".agent-authenticator" / ".key",
    )
)

_DIGESTS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}
_T = TypeVar("_T")


def _utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _vault_lock_path() -> Path:
    return VAULT_PATH.with_suffix(".lock")


def _key_lock_path() -> Path:
    return KEY_PATH.with_name(f"{KEY_PATH.name}.lock")


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        # Best effort. Some filesystems and platforms ignore chmod semantics.
        pass


def generate_key() -> str:
    """Generate a new Fernet key as a UTF-8 string."""
    return Fernet.generate_key().decode()


def write_key_file(path: Path, key: str) -> Path:
    """Persist a Fernet key to disk with private permissions."""
    normalized = key.strip()
    try:
        Fernet(normalized.encode())
    except Exception as exc:  # pragma: no cover - cryptography message is enough
        raise ValueError("Key must be a valid Fernet key.") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized, encoding="utf-8")
    _chmod_private(path)
    return path


def _get_fernet() -> Fernet:
    key = os.environ.get("AGENT_AUTH_KEY")
    if key:
        try:
            return Fernet(key.encode())
        except Exception as exc:  # pragma: no cover - cryptography validates
            raise ValueError(
                "AGENT_AUTH_KEY is not a valid Fernet key. "
                "Generate one with `agent-authenticator keygen`."
            ) from exc

    key_lock = FileLock(str(_key_lock_path()), timeout=10)
    with key_lock:
        if KEY_PATH.exists():
            return Fernet(KEY_PATH.read_bytes().strip())

        key_bytes = Fernet.generate_key()
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        KEY_PATH.write_bytes(key_bytes)
        _chmod_private(KEY_PATH)
        return Fernet(key_bytes)


def _normalize_account_name(account: str) -> str:
    normalized = account.strip()
    if not normalized:
        raise ValueError("Account name cannot be empty.")
    return normalized


def _normalize_secret(secret: str) -> str:
    normalized = secret.strip().replace(" ", "").upper()
    if not normalized:
        raise ValueError("Secret cannot be empty.")
    try:
        pyotp.TOTP(normalized).now()
    except Exception as exc:
        raise ValueError("Secret must be a valid base32 TOTP secret.") from exc
    return normalized


def _normalize_algorithm(algorithm: str) -> str:
    normalized = algorithm.strip().upper()
    if normalized not in _DIGESTS:
        supported = ", ".join(sorted(_DIGESTS))
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Use one of: {supported}.")
    return normalized


def _validate_digits(digits: int) -> int:
    if not 6 <= digits <= 10:
        raise ValueError("Digits must be between 6 and 10.")
    return digits


def _validate_period(period: int) -> int:
    if period <= 0 or period > 300:
        raise ValueError("Period must be between 1 and 300 seconds.")
    return period


def _read_vault_unlocked() -> dict[str, Any]:
    if not VAULT_PATH.exists():
        return {"version": 1, "accounts": {}}
    with open(VAULT_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _save_vault_unlocked(vault_data: dict[str, Any]) -> None:
    VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        "w",
        dir=VAULT_PATH.parent,
        encoding="utf-8",
        prefix=f".{VAULT_PATH.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(vault_data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        tmp_path = Path(handle.name)
    _chmod_private(tmp_path)
    os.replace(tmp_path, VAULT_PATH)
    _chmod_private(VAULT_PATH)


def _read_vault() -> dict[str, Any]:
    lock = FileLock(str(_vault_lock_path()), timeout=10)
    with lock:
        return _read_vault_unlocked()


def _mutate_vault(mutator: Callable[[dict[str, Any]], _T]) -> _T:
    lock = FileLock(str(_vault_lock_path()), timeout=10)
    with lock:
        vault_data = _read_vault_unlocked()
        result = mutator(vault_data)
        _save_vault_unlocked(vault_data)
        return result


def list_accounts() -> list[str]:
    vault_data = _read_vault()
    return sorted(vault_data.get("accounts", {}).keys())


def get_account_info(account: str) -> dict[str, Any]:
    account_name = _normalize_account_name(account)
    vault_data = _read_vault()
    accounts = vault_data.get("accounts", {})
    if account_name not in accounts:
        raise ValueError(f"Account '{account_name}' not found.")
    entry = accounts[account_name]
    return {
        "account": account_name,
        "issuer": entry.get("issuer", ""),
        "digits": entry.get("digits", 6),
        "period": entry.get("period", 30),
        "algorithm": entry.get("algorithm", "SHA1"),
        "added_at": entry.get("added_at", ""),
    }


def generate_totp(account: str) -> str:
    account_name = _normalize_account_name(account)
    fernet = _get_fernet()
    vault_data = _read_vault()
    accounts = vault_data.get("accounts", {})
    if account_name not in accounts:
        available = ", ".join(sorted(accounts)) or "(none)"
        raise ValueError(
            f"Account '{account_name}' not found. Available accounts: {available}."
        )
    entry = accounts[account_name]
    secret = fernet.decrypt(entry["secret"].encode()).decode()
    algorithm = _normalize_algorithm(entry.get("algorithm", "SHA1"))
    totp = pyotp.TOTP(
        secret,
        digits=_validate_digits(entry.get("digits", 6)),
        interval=_validate_period(entry.get("period", 30)),
        digest=_DIGESTS[algorithm],
    )
    return totp.now()


def add_account(
    account: str,
    secret: str,
    issuer: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    account_name = _normalize_account_name(account)
    normalized_secret = _normalize_secret(secret)
    normalized_algorithm = _normalize_algorithm(algorithm)
    normalized_digits = _validate_digits(digits)
    normalized_period = _validate_period(period)
    normalized_issuer = issuer.strip()
    fernet = _get_fernet()

    def mutate(vault_data: dict[str, Any]) -> str:
        accounts = vault_data.setdefault("accounts", {})
        accounts[account_name] = {
            "secret": fernet.encrypt(normalized_secret.encode()).decode(),
            "issuer": normalized_issuer,
            "digits": normalized_digits,
            "period": normalized_period,
            "algorithm": normalized_algorithm,
            "added_at": _utcnow(),
        }
        return f"Added '{account_name}' ({len(accounts)} accounts total)"

    return _mutate_vault(mutate)


def add_from_uri(account: str, otpauth_uri: str) -> str:
    parsed = pyotp.parse_uri(otpauth_uri)
    if not isinstance(parsed, pyotp.TOTP):
        raise ValueError("URI does not contain a TOTP secret (it may be HOTP).")
    digest = getattr(parsed, "digest", hashlib.sha1)
    algorithm = next(
        (
            name
            for name, digest_fn in _DIGESTS.items()
            if digest == digest_fn or getattr(digest, "__name__", "") == digest_fn.__name__
        ),
        "SHA1",
    )
    return add_account(
        account=account,
        secret=parsed.secret,
        issuer=parsed.issuer or "",
        digits=parsed.digits,
        period=parsed.interval,
        algorithm=algorithm,
    )


def remove_account(account: str) -> str:
    account_name = _normalize_account_name(account)

    def mutate(vault_data: dict[str, Any]) -> str:
        accounts = vault_data.get("accounts", {})
        if account_name not in accounts:
            raise ValueError(f"Account '{account_name}' not found.")
        del accounts[account_name]
        vault_data["accounts"] = accounts
        return f"Removed '{account_name}' ({len(accounts)} accounts remaining)"

    return _mutate_vault(mutate)

