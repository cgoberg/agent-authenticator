FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN python -m pip install --no-cache-dir .

VOLUME /data
ENV AGENT_AUTH_VAULT=/data/vault.json
ENV AGENT_AUTH_KEY_FILE=/data/.key
ENV AGENT_AUTH_AUDIT=/data/audit.jsonl

EXPOSE 8200

ENTRYPOINT ["agent-authenticator"]
CMD ["serve", "--transport", "http", "--host", "127.0.0.1", "--port", "8200", "--path", "/mcp"]
