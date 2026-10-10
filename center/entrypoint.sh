#!/bin/sh
# Apply DB migrations, then start the API. Keeps `docker compose up` a
# single reproducible step (DoD: clean machine, no manual edits).
set -e

echo "[entrypoint] running alembic migrations..."
alembic upgrade head

echo "[entrypoint] seeding demo operator/profiles/honeypots (idempotent)..."
PYTHONPATH=/app python scripts/seed.py || echo "[entrypoint] seed skipped/failed (continuing)"

echo "[entrypoint] starting uvicorn..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
