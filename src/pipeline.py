
"""End-to-end evidence import pipeline for ThreatGraph."""

from dataclasses import dataclass
from pathlib import Path

from .database import ThreatGraphDB, calculate_sha256
from .extractors import extract_from_line
from .ingestion import ingest_file
from .normalize import (
    hash_type,
    normalize_domain,
    normalize_hash,
    normalize_ipv4,
    normalize_path,
    normalize_url,
)


@dataclass(frozen=True)
class ImportResult:
    sample_id: str
    import_id: int
    source_file: str
    file_sha256: str
    skipped_duplicate: bool
    records_processed: int
    occurrences_added: int


_NORMALIZERS = {
    "md5": normalize_hash,
    "sha1": normalize_hash,
    "sha256": normalize_hash,
    "ipv4": normalize_ipv4,
    "domain": normalize_domain,
    "url": normalize_url,
    "filepath": normalize_path,
}


def _normalize_candidate(candidate):
    """Validate and canonicalize an extracted IOC."""
    normalizer = _NORMALIZERS.get(candidate.ioc_type)
    if normalizer is None:
        return None

    canonical = normalizer(candidate.canonical)
    if canonical is None:
        return None

    if (
        candidate.ioc_type in {"md5", "sha1", "sha256"}
        and hash_type(canonical) != candidate.ioc_type
    ):
        return None

    return canonical


def import_evidence(
    db: ThreatGraphDB,
    sample_id: str,
    file_path: str | Path,
    description: str | None = None,
) -> ImportResult:
    """Import evidence atomically, preserving each IOC occurrence's provenance."""
    path = Path(file_path)

    # Parse and validate the evidence before writing to the database.
    records = ingest_file(path)
    file_hash = calculate_sha256(path)
    source_file = path.name

    occurrences_added = 0

    with db.transaction() as conn:
        db.add_sample(sample_id, description=description, conn=conn)

        import_id, created = db.add_import(
            sample_id=sample_id,
            source_file=source_file,
            file_sha256=file_hash,
            conn=conn,
        )

        if not created:
            return ImportResult(
                sample_id=sample_id,
                import_id=import_id,
                source_file=source_file,
                file_sha256=file_hash,
                skipped_duplicate=True,
                records_processed=len(records),
                occurrences_added=0,
            )

        for record in records:
            # TXT/LOG records already have individual line locations.
            # CSV and JSON values can contain multiple lines, so retain
            # their original row/column or JSON path as the base location.
            lines = record.text.splitlines() or [record.text]

            for line_index, line in enumerate(lines, start=1):
                candidates = extract_from_line(line)

                for candidate in candidates:
                    canonical = _normalize_candidate(candidate)
                    if canonical is None:
                        continue

                    location = record.location
                    if len(lines) > 1:
                        location = f"{location}:text-line:{line_index}"

                    db.add_occurrence(
                        sample_id=sample_id,
                        import_id=import_id,
                        ioc_type=candidate.ioc_type,
                        canonical_value=canonical,
                        original_text=candidate.original,
                        source_file=record.source_file,
                        file_type=record.file_type,
                        location=location,
                        extraction_method=candidate.method,
                        conn=conn,
                    )
                    occurrences_added += 1

    return ImportResult(
        sample_id=sample_id,
        import_id=import_id,
        source_file=source_file,
        file_sha256=file_hash,
        skipped_duplicate=False,
        records_processed=len(records),
        occurrences_added=occurrences_added,
    )
