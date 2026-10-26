# Genesis Mesh MCP over Streamable HTTP with OAuth (docs/http-transport.md).
FROM python:3.12-slim

RUN useradd --system --uid 10001 --home-dir /var/lib/genesismesh-mcp --create-home --shell /usr/sbin/nologin mcp

WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in requirements.lock conftest.py ./
COPY src ./src
COPY docs ./docs
COPY scripts ./scripts
RUN pip install --no-cache-dir -c requirements.lock . && rm -rf /src

USER mcp
WORKDIR /var/lib/genesismesh-mcp
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=4)"]
ENTRYPOINT ["genesismesh-mcp-http"]
CMD ["--config", "/config/settings.json", "--remote", "/config/remote.json"]
