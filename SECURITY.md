# Security Policy

Agent Authenticator handles materials that are security-sensitive by nature.

## Supported Versions

Only the latest published release is considered supported for security fixes.

## Reporting a Vulnerability

Please report high-severity findings privately to:

- `carl-gustav@forgenord.com`

Include:

- affected version
- reproduction steps
- impact assessment
- any mitigation you recommend

## Security Expectations

- prefer `AGENT_AUTH_KEY` over colocated key files
- keep the service on `stdio` or loopback HTTP unless you have a strong reason
- never expose remote HTTP without an authenticated network boundary
- treat audit logs and vault paths as sensitive operational metadata
