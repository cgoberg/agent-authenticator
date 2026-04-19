# Contributing

Thanks for improving Agent Authenticator.

## Development Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## Common Commands

```bash
make test
make build
make lint
```

## Scope

This project is intentionally narrow. Good contributions tend to be:

- security hardening
- MCP ergonomics
- packaging and release hygiene
- documentation improvements grounded in real usage

Please avoid broadening the product into a general secrets manager.

## Pull Requests

- keep PRs focused
- include tests for behavior changes
- update docs when public behavior changes
- call out security tradeoffs explicitly

## Reporting Sensitive Issues

Please do not open public issues for secret leakage, authentication bypass, or
other high-severity security findings. Use the process in `SECURITY.md`.
