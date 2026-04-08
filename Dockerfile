FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/skill-scanner-venv \
    PATH="/opt/skill-scanner-venv/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/skill-scanner-venv

COPY pyproject.toml uv.lock README.md ./
COPY .git/ ./.git/
COPY skill_scanner/ ./skill_scanner/

RUN /opt/skill-scanner-venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/skill-scanner-venv/bin/pip install .

EXPOSE 8000

CMD ["/opt/skill-scanner-venv/bin/skill-scanner-api", "--host", "0.0.0.0", "--port", "8000"]
