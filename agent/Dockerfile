# Honeypot-host image: the agent process also starts the honeypot listeners
# in the same event loop (agent + honeypot co-located per host; see DESIGN
# ADR-3). Build context is the repo root so both packages are available.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN pip install --upgrade pip && pip install "httpx>=0.27,<0.28"

COPY agent/honeyagent /app/honeyagent
COPY honeypots /app/honeypots

CMD ["python", "-m", "honeyagent.main"]
