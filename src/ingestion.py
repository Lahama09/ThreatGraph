
"""Read supported evidence files while preserving source locations."""

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


SUPPORTED_EXTENSIONS = {".txt", ".log", ".csv", ".json"}
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB


@dataclass(frozen=True)
class EvidenceRecord:
    """One piece of text extracted from an evidence file."""

    source_file: str
    file_type: str
    location: str
    text: str


def _decode_text(raw: bytes) -> str:
    """Decode evidence text without executing its contents."""
    return raw.decode("utf-8-sig", errors="replace")


def ingest_file(
    file_path: str | Path,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[EvidenceRecord]:
    """
    Read a TXT, LOG, CSV, or JSON file.

    TXT/LOG locations use line numbers.
    CSV locations use data-row numbers and column names.
    JSON locations use JSON paths.

    The function reads evidence as data; it never executes it.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    extension = path.suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported evidence format: {extension or '(no extension)'}")

    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive")

    file_size = path.stat().st_size
    if file_size > max_file_bytes:
        raise ValueError(
            f"File exceeds the size limit of {max_file_bytes} bytes"
        )

    raw = path.read_bytes()
    source_file = path.name
    file_type = extension[1:]
    content = _decode_text(raw)

    if extension in {".txt", ".log"}:
        return [
            EvidenceRecord(
                source_file=source_file,
                file_type=file_type,
                location=f"line:{line_number}",
                text=line,
            )
            for line_number, line in enumerate(content.splitlines(), start=1)
            if line.strip()
        ]

    if extension == ".csv":
        return _ingest_csv(content, source_file, file_type)

    return _ingest_json(content, source_file, file_type)


def _ingest_csv(
    content: str,
    source_file: str,
    file_type: str,
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []

    reader = csv.DictReader(content.splitlines())
    if not reader.fieldnames:
        return records

    for row_number, row in enumerate(reader, start=2):
        for column, value in row.items():
            if column is None or value is None or not value.strip():
                continue

            records.append(
                EvidenceRecord(
                    source_file=source_file,
                    file_type=file_type,
                    location=f"row:{row_number}/column:{column}",
                    text=value,
                )
            )

    return records


def _walk_json(
    value: object,
    location: str = "$",
) -> Iterator[tuple[str, str]]:
    """Yield string values with paths through nested JSON structures."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_json(child, f"{location}.{key}")

    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json(child, f"{location}[{index}]")

    elif isinstance(value, str) and value.strip():
        yield location, value

    elif isinstance(value, (int, float, bool)):
        yield location, str(value)


def _ingest_json(
    content: str,
    source_file: str,
    file_type: str,
) -> list[EvidenceRecord]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON evidence: {exc.msg} at line {exc.lineno}"
        ) from exc

    return [
        EvidenceRecord(
            source_file=source_file,
            file_type=file_type,
            location=location,
            text=value,
        )
        for location, value in _walk_json(document)
    ]
