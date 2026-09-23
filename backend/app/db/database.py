"""SQLAlchemy models, migrations and session management for scan history.

Storage contract for the ``scan_history`` table:

    id                   PK, autoincrement
    url                  submitted URL (truncated to 2048 chars)
    normalized_url       normalized URL (truncated to 2048 chars)
    url_hash             SHA-256 hex digest of normalized_url (indexed lookup key)
    prediction           LEGITIMATE | SUSPICIOUS | PHISHING
    confidence           float 0-100
    risk_score           int 0-100
    probability_phishing float 0-1
    model_name           serving model name
    model_version        serving model version
    client_ip            optional, for abuse analysis
    created_at           UTC timestamp

Migrations are handled by ``run_migrations()``: an idempotent, version-tracked
sequence of safe DDL statements (additive columns + indexes only). It runs on
API startup and is also exposed via ``python -m app.db.migrate`` so operators
can run it as a one-off (Render/CI) without booting the API.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import (
    Float,
    Integer,
    String,
    Text,
    case,
    create_engine,
    desc,
    func,
    select,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.config import get_settings

logger = logging.getLogger("app.db")

MAX_STORED_URL_LENGTH = 2048

# Risk-score band boundaries (inclusive); shared with the analytics endpoint so
# the UI labels and the SQL grouping cannot drift apart.
RISK_LOW_MAX = 34
RISK_HIGH_MIN = 75


def url_hash(normalized_url: str) -> str:
    """SHA-256 of the normalized URL — a stable lookup key for repeat scans."""
    return hashlib.sha256((normalized_url or "").encode("utf-8")).hexdigest()


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    prediction: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    probability_phishing: Mapped[float] = mapped_column(Float, nullable=False)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    client_ip: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))


# --------------------------------------------------------------------------- #
# Engine / session management
# --------------------------------------------------------------------------- #
_engine = None
_session_factory = None


def _connect_args(url: str) -> dict:
    """SQLite needs check_same_thread=False under TestClient; PostgreSQL needs none."""
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def get_engine():
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            connect_args=_connect_args(settings.database_url),
        )
        Base.metadata.create_all(_engine)
        _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def reset_engine() -> None:
    """Dispose and forget the engine (used by tests to rebind DATABASE_URL)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def record_scan(payload: dict, client_ip: str | None = None) -> int | None:
    """Persist one scan; returns the row id or None when history is disabled
    or the DB is unreachable (history must never break prediction)."""
    settings = get_settings()
    if not settings.history_enabled:
        return None
    try:
        get_engine()
        normalized = (payload.get("normalized_url") or payload.get("url") or "")[:MAX_STORED_URL_LENGTH]
        with _session_factory() as session:
            rec = ScanRecord(
                url=(payload.get("url") or "")[:MAX_STORED_URL_LENGTH],
                normalized_url=normalized,
                url_hash=url_hash(normalized),
                prediction=payload["prediction"],
                confidence=float(payload["confidence"]),
                risk_score=int(payload["risk_score"]),
                probability_phishing=float(payload["probability_phishing"]),
                model_name=payload.get("model_name", "unknown"),
                model_version=payload.get("model_version", "unknown"),
                client_ip=(client_ip or "")[:64],
            )
            session.add(rec)
            session.commit()
            return rec.id
    except Exception:  # noqa: BLE001 - history is best-effort
        logger.exception("Scan history write failed (prediction result is still returned)")
        return None


def get_scan_by_hash(normalized_url: str) -> ScanRecord | None:
    """Most recent scan of the same normalized URL, or None."""
    settings = get_settings()
    if not settings.history_enabled:
        return None
    try:
        get_engine()
        with _session_factory() as session:
            return session.execute(
                select(ScanRecord)
                .where(ScanRecord.url_hash == url_hash(normalized))
                .order_by(desc(ScanRecord.id))
                .limit(1)
            ).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        return None


def list_history(
    page: int = 1,
    page_size: int = 20,
    prediction: str | None = None,
) -> tuple[list[ScanRecord], int]:
    """Paginated scan history, newest first.

    Returns (rows, total_after_filter). Safe when history is disabled or the
    DB is unreachable (empty list, total 0). Page/size are clamped defensively.
    """
    page = max(1, int(page))
    page_size = min(100, max(1, int(page_size)))
    settings = get_settings()
    if not settings.history_enabled:
        return [], 0
    try:
        get_engine()
        with _session_factory() as session:
            stmt = select(ScanRecord)
            count_stmt = select(func.count(ScanRecord.id))
            if prediction:
                stmt = stmt.where(ScanRecord.prediction == prediction)
                count_stmt = count_stmt.where(ScanRecord.prediction == prediction)
            total = session.scalar(count_stmt) or 0
            rows = (
                session.execute(
                    stmt.order_by(desc(ScanRecord.id))
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
                .scalars()
                .all()
            )
            return list(rows), int(total)
    except Exception:  # noqa: BLE001
        logger.exception("History read failed (serving empty page)")
        return [], 0


def history_stats() -> dict:
    """Aggregate counters for /model-info; best-effort, safe when disabled."""
    settings = get_settings()
    if not settings.history_enabled:
        return {"enabled": False}
    try:
        get_engine()
        with _session_factory() as session:
            total = session.scalar(select(func.count(ScanRecord.id))) or 0
            phish = session.scalar(
                select(func.count(ScanRecord.id)).where(ScanRecord.prediction == "PHISHING")
            ) or 0
            return {"enabled": True, "total_scans": total, "phishing_detected": phish}
    except Exception:  # noqa: BLE001
        return {"enabled": True, "total_scans": 0, "phishing_detected": 0, "error": "unavailable"}


def history_aggregate() -> dict:
    """Counters over the *entire* scan history, grouped in the database.

    Two grouped queries (verdict, risk band) plus a row count, instead of
    paging every row to the caller — so the figures cover the whole table no
    matter how large it grows. Returns the shape of
    ``ScanHistoryStatsResponse``; all zeros when history is disabled or the DB
    is unreachable (analytics must never break the page).
    """
    empty = {
        "total": 0,
        "counts": {"LEGITIMATE": 0, "SUSPICIOUS": 0, "PHISHING": 0},
        "risk_bands": {"low": 0, "medium": 0, "high": 0},
    }
    settings = get_settings()
    if not settings.history_enabled:
        return empty
    try:
        get_engine()
        with _session_factory() as session:
            counts = dict(empty["counts"])
            for prediction, n in session.execute(
                select(ScanRecord.prediction, func.count(ScanRecord.id)).group_by(
                    ScanRecord.prediction
                )
            ).all():
                if prediction in counts:
                    counts[prediction] = int(n)

            band = case(
                (ScanRecord.risk_score <= RISK_LOW_MAX, "low"),
                (ScanRecord.risk_score < RISK_HIGH_MIN, "medium"),
                else_="high",
            )
            bands = dict(empty["risk_bands"])
            for name, n in session.execute(
                select(band, func.count(ScanRecord.id)).group_by(band)
            ).all():
                if name in bands:
                    bands[name] = int(n)

            total = int(session.scalar(select(func.count(ScanRecord.id))) or 0)
            return {"total": total, "counts": counts, "risk_bands": bands}
    except Exception:  # noqa: BLE001
        logger.exception("History aggregate failed (serving zeros)")
        return empty


# --------------------------------------------------------------------------- #
# Migrations (idempotent, version-tracked)
# --------------------------------------------------------------------------- #
# (version, [DDL statements]) — additive-only DDL; never drops or rewrites data.
# Statement text must be valid on both PostgreSQL and SQLite.
MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, [
        "CREATE INDEX IF NOT EXISTS ix_scan_history_prediction ON scan_history (prediction)",
        "CREATE INDEX IF NOT EXISTS ix_scan_history_created_at ON scan_history (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_scan_history_url_hash ON scan_history (url_hash)",
    ]),
    (2, ["ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS url_hash VARCHAR(64)"]),
]

LATEST_SCHEMA_VERSION = 2


def _backfill_url_hashes(conn) -> int:
    """One-time backfill for rows created before url_hash existed.

    Uses explicit parameterized UPDATE statements on the active connection:
    objects loaded through a bare Connection have no Session unit-of-work,
    so in-place ORM mutation would never be flushed/committed. Only legacy
    rows with an empty or NULL url_hash are touched; hashing reuses the
    canonical url_hash() implementation (normalized_url, else raw url).
    """
    from sqlalchemy import or_, update

    rows = conn.execute(
        select(ScanRecord.id, ScanRecord.normalized_url, ScanRecord.url).where(
            or_(ScanRecord.url_hash == "", ScanRecord.url_hash.is_(None))
        )
    ).all()
    if not rows:
        return 0
    updated = 0
    for row_id, normalized, raw in rows:
        conn.execute(
            update(ScanRecord)
            .where(ScanRecord.id == row_id)
            .values(url_hash=url_hash(normalized or raw or ""))
        )
        updated += 1
    return updated


def run_migrations() -> int:
    """Apply all pending migrations. Idempotent: safe to call at every boot
    and concurrently from multiple workers. Returns the latest applied version
    (or -1 when migration could not run; boot continues with create_all schema).

    Uses ``ADD COLUMN IF NOT EXISTS`` (PostgreSQL 9.6+, SQLite 3.35+); on older
    SQLite builds the duplicate-column error is swallowed as a no-op.
    """
    try:
        engine = get_engine()
        with engine.begin() as conn:
            Base.metadata.create_all(conn)  # fresh installs get the full schema

            # Databases created before url_hash existed need the column added
            # before the versioned migration bookkeeping below.
            has_url_hash = True
            try:
                conn.execute(text("SELECT url_hash FROM scan_history LIMIT 1"))
            except Exception:  # noqa: BLE001
                try:
                    conn.execute(text("ALTER TABLE scan_history ADD COLUMN url_hash VARCHAR(64)"))
                except Exception:  # noqa: BLE001
                    has_url_hash = False

            if has_url_hash:
                try:
                    migrated = _backfill_url_hashes(conn)
                    if migrated:
                        logger.info("Backfilled url_hash for %d legacy scan rows", migrated)
                except Exception:  # noqa: BLE001
                    pass

            for version, statements in MIGRATIONS:
                applied = conn.execute(
                    select(SchemaMigration).where(SchemaMigration.version == version)
                ).scalar_one_or_none()
                if applied is not None:
                    continue
                for ddl in statements:
                    try:
                        conn.execute(text(ddl))
                    except Exception as exc:  # noqa: BLE001
                        # 'IF NOT EXISTS' unsupported (old SQLite) or duplicate
                        # column: treat as already-applied, not a failure.
                        logger.debug("Migration %s statement skipped: %s", version, exc)
                conn.execute(
                    SchemaMigration.__table__.insert().values(version=version)
                )
        return LATEST_SCHEMA_VERSION
    except Exception:  # noqa: BLE001 - migrations must never block boot
        logger.exception("Schema migration failed (continuing with create_all schema)")
        return -1
