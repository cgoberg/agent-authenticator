"""Lightweight JSONL audit logging for agent-authenticator."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from filelock import FileLock

_AUDIT_ENV = os.environ.get("AGENT_AUTH_AUDIT")
AUDIT_PATH = (
    None
    if _AUDIT_ENV == ""
    else Path(_AUDIT_ENV)
    if _AUDIT_ENV is not None
    else Path.home() / ".agent-authenticator" / "audit.jsonl"
)


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass


def _audit_lock_path() -> Path | None:
    if AUDIT_PATH is None:
        return None
    return AUDIT_PATH.with_suffix(".lock")


def log(action: str, account: str, result: str = "ok") -> None:
    if AUDIT_PATH is None:
        return

    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "account": account,
        "result": result,
    }
    lock = FileLock(str(_audit_lock_path()), timeout=5)
    with lock:
        with open(AUDIT_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        _chmod_private(AUDIT_PATH)

