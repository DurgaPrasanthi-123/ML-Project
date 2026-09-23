#!/bin/sh
set -e

# Idempotent schema migrations; skip with SKIP_MIGRATIONS=1 if desired.
if [ "${SKIP_MIGRATIONS:-0}" != "1" ]; then
  echo "Running database migrations..."
  python -m app.db.migrate || {
    echo "Migrations failed; aborting start (set SKIP_MIGRATIONS=1 to bypass)." >&2
    exit 1
  }
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
