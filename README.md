# Agent Authenticator

[![CI](https://github.com/cgoberg/agent-authenticator/actions/workflows/ci.yml/badge.svg)](https://github.com/cgoberg/agent-authenticator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-111111.svg)](LICENSE)

Encrypted local TOTP vault for MCP agents.

`agent-authenticator` is a self-hostable MCP server that stores TOTP secrets in
an encrypted local vault and generates one-time codes on demand for AI agents.
It is designed for the real workflow: Claude Code, Cursor, or another agent
needs a 2FA code, but should never see or persist the underlying secret.

## Launch Links

- Project page: https://forgenord.com/projects#agent-authenticator
- Forge Nord dispatch: https://forgenord.com/dispatches/agent-authenticator

## Scope

- Agents increasingly need to complete authenticated workflows.
- Most authenticator apps are built for humans tapping a phone, not tools.
- Copying raw TOTP seeds into prompts, notes, or scripts is a bad trade.

Agent Authenticator exposes a narrow interface:

- encrypted vault at rest
- current code generation on demand
- zero secret exposure through the MCP tool surface
- audit log for security-sensitive actions

## Defaults

The default behavior is conservative:

- local-first by default
- loopback-only HTTP by default
- explicit opt-in for remote HTTP binding
- first-run key setup without printing secrets to standard output

## MCP Tools

| Tool | Purpose |
| --- | --- |
| `list_accounts()` | List available account names |
| `get_account_info(account)` | Show safe metadata without returning the secret |
| `generate_totp(account)` | Generate the current TOTP code |
| `add_account(account, secret, ...)` | Add an account from a base32 secret |
| `add_from_uri(account, otpauth_uri)` | Add an account from an `otpauth://` URI |
| `remove_account(account)` | Remove an account from the vault |

## Install

```bash
pip install agent-authenticator
```

You can also run from source:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## Quick Start

Generate an environment-managed key:

```bash
agent-authenticator keygen --format shell
```

Run locally over stdio:

```bash
agent-authenticator
```

Add it to your MCP client config:

```json
{
  "mcpServers": {
    "authenticator": {
      "command": "agent-authenticator"
    }
  }
}
```

Inspect the local setup:

```bash
agent-authenticator doctor
```

## Add Your First Account

When a service enables authenticator-based 2FA, it often exposes an
`otpauth://` URI under the QR code:

```text
otpauth://totp/X.com:stella@forge.se?secret=JBSWY3DPEHPK3PXP&issuer=X.com
```

Tell your agent:

> Add a TOTP account called `x-stella` from this URI: `otpauth://totp/...`

Or add it directly:

> Add a TOTP account called `x-stella` with secret `JBSWY3DPEHPK3PXP` and issuer `X.com`

Then when you need a code:

> Generate a TOTP code for `x-stella`

## Security Model

### What it does well

- Secrets are encrypted at rest with Fernet.
- The MCP tool surface never returns the seed.
- Vault mutations are lock-protected to avoid concurrent corruption.
- Audit logs can be enabled or disabled explicitly.
- Vault, key, and audit files are written with private file permissions where supported.

### What it does not do for you

- It does not protect against a compromised host.
- It does not authenticate HTTP clients by itself.
- It does not replace a hardware-backed secret store.

### Default paths

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENT_AUTH_KEY` | unset | Preferred Fernet key source |
| `AGENT_AUTH_KEY_FILE` | `~/.agent-authenticator/.key` | Fallback key file |
| `AGENT_AUTH_VAULT` | `~/.agent-authenticator/vault.json` | Encrypted vault |
| `AGENT_AUTH_AUDIT` | `~/.agent-authenticator/audit.jsonl` | Audit log, or set to empty string to disable |
| `AGENT_AUTH_HOST` | `127.0.0.1` | Default HTTP host |
| `AGENT_AUTH_PORT` | `8200` | Default HTTP port |
| `AGENT_AUTH_HTTP_PATH` | `/mcp` | Default HTTP mount path |

## HTTP Transport

Loopback-only HTTP:

```bash
agent-authenticator serve --transport http --host 127.0.0.1 --port 8200
```

Then connect with:

```json
{
  "mcpServers": {
    "authenticator": {
      "type": "http",
      "url": "http://127.0.0.1:8200/mcp/"
    }
  }
}
```

Remote bind requires an explicit flag:

```bash
agent-authenticator serve \
  --transport http \
  --host 0.0.0.0 \
  --port 8200 \
  --allow-remote-http
```

Use that only behind real network controls such as a reverse proxy, mTLS, VPN,
or another authenticated boundary.

## Docker

Build locally:

```bash
docker build -t forge-nord/agent-authenticator .
```

Run with loopback-only HTTP inside the container:

```bash
docker run \
  -v ~/.agent-authenticator:/data \
  -e AGENT_AUTH_KEY='replace-me-with-agent-authenticator-keygen-output' \
  forge-nord/agent-authenticator
```

To expose it outside the container, override the command deliberately:

```bash
docker run \
  -p 8200:8200 \
  -v ~/.agent-authenticator:/data \
  -e AGENT_AUTH_KEY='replace-me-with-agent-authenticator-keygen-output' \
  forge-nord/agent-authenticator \
  serve --transport http --host 0.0.0.0 --port 8200 --allow-remote-http
```

## Local Development

```bash
make install
make test
make build
```

## Release Checklist

- `make test`
- `make build`
- confirm `agent-authenticator --help`
- confirm `agent-authenticator doctor`
- tag release and publish artifacts

## License

MIT © Forge Nord
