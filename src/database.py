
"""SQLite storage for ThreatGraph evidence and indicators."""

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def calculate_sha256(file_path: str | Path) -> str:
    """Calculate a file's SHA-256 digest without loading it all into memory."""
    digest = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


class ThreatGraphDB:
    """Database access layer for ThreatGraph."""

    def __init__(self, db_path: str | Path = "data/threatgraph.db"):
        self.db_path = str(db_path)

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")

        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Group several database operations into one atomic transaction."""
        with self._connection() as conn:
            with conn:
                yield conn

    def initialize(self) -> None:
        """Create the database schema if it does not exist."""
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS samples (
                    sample_id TEXT PRIMARY KEY,
                    description TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS indicators (
                    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    canonical_value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (ioc_type, canonical_value)
                );

                CREATE TABLE IF NOT EXISTS imports (
                    import_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_id TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    file_sha256 TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    FOREIGN KEY (sample_id)
                        REFERENCES samples(sample_id),
                    UNIQUE (sample_id, file_sha256)
                );

                CREATE TABLE IF NOT EXISTS evidence_occurrences (
                    occurrence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_id TEXT NOT NULL,
                    indicator_id INTEGER NOT NULL,
                    import_id INTEGER NOT NULL,
                    source_file TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    location TEXT NOT NULL,
                    original_text TEXT NOT NULL,
                    extraction_method TEXT,
                    source_timestamp TEXT,
                    imported_at TEXT NOT NULL,
                    FOREIGN KEY (sample_id)
                        REFERENCES samples(sample_id),
                    FOREIGN KEY (indicator_id)
                        REFERENCES indicators(indicator_id),
                    FOREIGN KEY (import_id)
                        REFERENCES imports(import_id)
                );

                CREATE INDEX IF NOT EXISTS idx_occurrences_sample
                    ON evidence_occurrences(sample_id);

                CREATE INDEX IF NOT EXISTS idx_occurrences_indicator
                    ON evidence_occurrences(indicator_id);

                CREATE INDEX IF NOT EXISTS idx_imports_sample
                    ON imports(sample_id);
                """
            )

    def add_sample(
        self,
        sample_id: str,
        description: str | None = None,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        """Create a sample record; existing IDs are left unchanged."""
        if conn is not None:
            conn.execute(
                """
                INSERT OR IGNORE INTO samples
                    (sample_id, description, created_at)
                VALUES (?, ?, ?)
                """,
                (sample_id, description, utc_now()),
            )
            return

        with self._connection() as connection:
            self.add_sample(sample_id, description, conn=connection)

    def add_import(
        self,
        sample_id: str,
        source_file: str,
        file_sha256: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> tuple[int, bool]:
        """
        Record an imported file.

        Returns (import_id, created).
        The same file can be associated with different samples.
        """
        if conn is None:
            with self._connection() as connection:
                return self.add_import(
                    sample_id, source_file, file_sha256, conn=connection
                )

        existing = conn.execute(
            """
            SELECT import_id FROM imports
            WHERE sample_id = ? AND file_sha256 = ?
            """,
            (sample_id, file_sha256),
        ).fetchone()

        if existing:
            return existing["import_id"], False

        cursor = conn.execute(
            """
            INSERT INTO imports
                (sample_id, source_file, file_sha256, imported_at)
            VALUES (?, ?, ?, ?)
            """,
            (sample_id, source_file, file_sha256, utc_now()),
        )
        return cursor.lastrowid, True

    def add_indicator(
        self,
        ioc_type: str,
        canonical_value: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        """Return the ID of a unique canonical indicator."""
        if conn is None:
            with self._connection() as connection:
                return self.add_indicator(
                    ioc_type, canonical_value, conn=connection
                )

        conn.execute(
            """
            INSERT INTO indicators
                (ioc_type, canonical_value, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(ioc_type, canonical_value) DO NOTHING
            """,
            (ioc_type, canonical_value, utc_now()),
        )

        row = conn.execute(
            """
            SELECT indicator_id FROM indicators
            WHERE ioc_type = ? AND canonical_value = ?
            """,
            (ioc_type, canonical_value),
        ).fetchone()

        return row["indicator_id"]

    def add_occurrence(
        self,
        *,
        sample_id: str,
        import_id: int,
        ioc_type: str,
        canonical_value: str,
        original_text: str,
        source_file: str,
        file_type: str,
        location: str,
        extraction_method: str | None = None,
        source_timestamp: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        """Store an evidence occurrence without discarding duplicates."""
        if conn is None:
            with self._connection() as connection:
                return self.add_occurrence(
                    sample_id=sample_id,
                    import_id=import_id,
                    ioc_type=ioc_type,
                    canonical_value=canonical_value,
                    original_text=original_text,
                    source_file=source_file,
                    file_type=file_type,
                    location=location,
                    extraction_method=extraction_method,
                    source_timestamp=source_timestamp,
                    conn=connection,
                )

        indicator_id = self.add_indicator(
            ioc_type, canonical_value, conn=conn
        )

        cursor = conn.execute(
            """
            INSERT INTO evidence_occurrences (
                sample_id, indicator_id, import_id,
                source_file, file_type, location, original_text,
                extraction_method, source_timestamp, imported_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_id,
                indicator_id,
                import_id,
                source_file,
                file_type,
                location,
                original_text,
                extraction_method,
                source_timestamp,
                utc_now(),
            ),
        )

        return cursor.lastrowid

    def count(self, table: str) -> int:
        """Count records in a known ThreatGraph table."""
        allowed_tables = {
            "samples",
            "indicators",
            "imports",
            "evidence_occurrences",
        }
        if table not in allowed_tables:
            raise ValueError(f"Unsupported table: {table}")

        with self._connection() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS total FROM {table}"
            ).fetchone()
            return row["total"]

    def get_indicators_for_sample(
        self, sample_id: str
    ) -> list[sqlite3.Row]:
        """Return indicators and their evidence locations for one sample."""
        with self._connection() as conn:
            return conn.execute(
                """
                SELECT
                    i.indicator_id,
                    i.ioc_type,
                    i.canonical_value,
                    e.source_file,
                    e.file_type,
                    e.location,
                    e.original_text,
                    e.extraction_method
                FROM evidence_occurrences AS e
                JOIN indicators AS i
                    ON i.indicator_id = e.indicator_id
                WHERE e.sample_id = ?
                ORDER BY e.occurrence_id
                """,
                (sample_id,),
            ).fetchall()
