FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp/ghost-home \
    TMPDIR=/tmp/ghost-audit-tmp \
    GHOST_AUDIT_DATA_DIR=/data \
    GHOST_AUDIT_MODE=development \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ghostaudit \
    && useradd --uid 10001 --gid ghostaudit --home-dir /home/ghostaudit --create-home --shell /usr/sbin/nologin ghostaudit \
    && mkdir -p /data /tmp/ghost-audit-tmp \
    && chown -R 10001:10001 /data /tmp/ghost-audit-tmp /home/ghostaudit \
    && tesseract --version

WORKDIR /app
COPY requirements-container.lock pyproject.toml README.md ./
COPY src/ghost_audit ./src/ghost_audit

RUN python -m pip install --no-cache-dir pip==25.2 \
    && python -m pip install --no-cache-dir -c requirements-container.lock ".[app,pdf,ocr]" \
    && mkdir -p /tmp/ghost-home \
    && chown -R 10001:10001 /tmp/ghost-home \
    && find /usr/local/lib/python3.13 -type d -name __pycache__ -prune -exec rm -rf {} +

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).read()"]
CMD ["uvicorn", "ghost_audit.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
