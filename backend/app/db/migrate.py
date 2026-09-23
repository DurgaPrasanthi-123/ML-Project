"""One-off migration runner: ``python -m app.db.migrate`` (from backend/).

Runs the same idempotent migrations as API startup without booting the API —
for Render jobs, CI, or operators. Exit code 0 when the schema is current.
"""

from __future__ import annotations

import sys

from app.db.database import LATEST_SCHEMA_VERSION, run_migrations


def main() -> int:
    version = run_migrations()
    if version == LATEST_SCHEMA_VERSION:
        print(f"Schema is current (version {version}).")
        return 0
    print(f"Migration failed (version={version}); see logs.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
