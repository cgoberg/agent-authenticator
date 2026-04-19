"""Agent Authenticator — Forge Nord's TOTP vault for MCP agents."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from fastmcp import FastMCP

from agent_authenticator import __version__, audit, vault

mcp = FastMCP("agent-authenticator")


@mcp.tool
def list_accounts() -> list[str]:
    """List all TOTP account names in the vault."""
    return vault.list_accounts()


@mcp.tool
def get_account_info(account: str) -> dict:
    """Return safe metadata for an account without exposing the secret."""
    return vault.get_account_info(account)


@mcp.tool
def generate_totp(account: str) -> str:
    """Generate a current TOTP code for the given account."""
    try:
        code = vault.generate_totp(account)
        audit.log("generate_totp", account, "ok")
        return code
    except ValueError as exc:
        audit.log("generate_totp", account, f"error: {exc}")
        raise


@mcp.tool
def add_account(
    account: str,
    secret: str,
    issuer: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """Add a TOTP account to the encrypted vault."""
    result = vault.add_account(account, secret, issuer, digits, period, algorithm)
    audit.log("add_account", account, "ok")
    return result


@mcp.tool
def add_from_uri(account: str, otpauth_uri: str) -> str:
    """Parse an otpauth:// URI and add the contained TOTP account."""
    result = vault.add_from_uri(account, otpauth_uri)
    audit.log("add_from_uri", account, "ok")
    return result


@mcp.tool
def remove_account(account: str) -> str:
    """Remove a TOTP account from the vault."""
    result = vault.remove_account(account)
    audit.log("remove_account", account, "ok")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-authenticator",
        description=(
            "Forge Nord's TOTP vault for MCP agents. Keep the secret cold. "
            "Hand the code to the model."
        ),
        epilog=(
            "Examples:\n"
            "  agent-authenticator\n"
            "  agent-authenticator serve --transport http --host 127.0.0.1 --port 8200\n"
            "  agent-authenticator keygen --format shell\n"
            "  agent-authenticator doctor --json"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser(
        "serve",
        help="Run the MCP server.",
        description="Run the MCP server over stdio or an HTTP-family transport.",
    )
    serve.add_argument(
        "--transport",
        choices=("stdio", "http", "streamable-http", "sse"),
        default="stdio",
        help="Transport to expose. Defaults to stdio.",
    )
    serve.add_argument(
        "--host",
        default=os.environ.get("AGENT_AUTH_HOST", "127.0.0.1"),
        help="Host to bind for HTTP-family transports. Defaults to 127.0.0.1.",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("AGENT_AUTH_PORT", "8200")),
        help="Port to bind for HTTP-family transports. Defaults to 8200.",
    )
    serve.add_argument(
        "--path",
        default=os.environ.get("AGENT_AUTH_HTTP_PATH", "/mcp"),
        help="Mount path for HTTP-family transports. Defaults to /mcp.",
    )
    serve.add_argument(
        "--banner",
        action="store_true",
        help="Show the FastMCP startup banner.",
    )
    serve.add_argument(
        "--allow-remote-http",
        action="store_true",
        help=(
            "Allow binding HTTP-family transports on non-loopback hosts. "
            "Use only behind real network controls."
        ),
    )

    keygen = subparsers.add_parser(
        "keygen",
        help="Generate a Fernet key for AGENT_AUTH_KEY.",
        description="Generate a Fernet key for env-based key management.",
    )
    keygen.add_argument(
        "--format",
        choices=("raw", "shell", "json"),
        default="shell",
        help="Output format. Defaults to shell.",
    )
    keygen.add_argument(
        "--write",
        type=Path,
        help="Optional path to write the key file with 0600 permissions.",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="Show local configuration and vault health.",
        description="Inspect the local vault, key source, and audit configuration.",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )

    return parser


def _coerce_legacy_args(argv: Sequence[str]) -> list[str]:
    args = list(argv)
    legacy_serve_flags = {
        "--transport",
        "--host",
        "--port",
        "--path",
        "--banner",
        "--allow-remote-http",
    }
    if not args:
        return ["serve", *args]
    if args[0] in legacy_serve_flags:
        return ["serve", *args]
    return args


def _key_source() -> str:
    if os.environ.get("AGENT_AUTH_KEY"):
        return "env"
    if vault.KEY_PATH.exists():
        return "file"
    return "not-initialized"


def _doctor_payload() -> dict[str, object]:
    return {
        "version": __version__,
        "vault_path": str(vault.VAULT_PATH),
        "vault_exists": vault.VAULT_PATH.exists(),
        "key_path": str(vault.KEY_PATH),
        "key_source": _key_source(),
        "audit_path": None if audit.AUDIT_PATH is None else str(audit.AUDIT_PATH),
        "audit_enabled": audit.AUDIT_PATH is not None,
        "account_count": len(vault.list_accounts()),
        "http_default_host": os.environ.get("AGENT_AUTH_HOST", "127.0.0.1"),
        "http_default_port": int(os.environ.get("AGENT_AUTH_PORT", "8200")),
    }


def _run_doctor(as_json: bool) -> int:
    payload = _doctor_payload()
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    lines = [
        "Agent Authenticator doctor",
        f"Version        {payload['version']}",
        f"Vault path      {payload['vault_path']}",
        f"Vault exists    {'yes' if payload['vault_exists'] else 'no'}",
        f"Key source      {payload['key_source']}",
        f"Key path        {payload['key_path']}",
        f"Audit enabled   {'yes' if payload['audit_enabled'] else 'no'}",
        f"Audit path      {payload['audit_path'] or '(disabled)'}",
        f"Accounts        {payload['account_count']}",
    ]
    print("\n".join(lines))
    return 0


def _run_keygen(output_format: str, write_path: Path | None) -> int:
    key = vault.generate_key()
    if write_path is not None:
        vault.write_key_file(write_path, key)

    if output_format == "raw":
        print(key)
    elif output_format == "json":
        payload = {"agent_auth_key": key}
        if write_path is not None:
            payload["written_to"] = str(write_path)
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        line = f"export AGENT_AUTH_KEY='{key}'"
        if write_path is not None:
            line += f"\n# Also written to {write_path}"
        print(line)
    return 0


def _ensure_safe_http_host(host: str, allow_remote_http: bool) -> None:
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if host not in loopback_hosts and not allow_remote_http:
        raise SystemExit(
            "Refusing to bind an HTTP transport on a non-loopback host without "
            "--allow-remote-http."
        )


def _run_serve(args: argparse.Namespace) -> int:
    if args.transport == "stdio":
        mcp.run(transport="stdio", show_banner=args.banner)
        return 0

    _ensure_safe_http_host(args.host, args.allow_remote_http)
    mcp.run(
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path,
        show_banner=args.banner,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_coerce_legacy_args(argv or sys.argv[1:]))

    if args.command == "keygen":
        return _run_keygen(args.format, args.write)
    if args.command == "doctor":
        return _run_doctor(args.json)
    return _run_serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
