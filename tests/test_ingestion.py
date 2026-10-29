
import json

import pytest

from src.ingestion import ingest_file


def test_text_file_preserves_line_numbers(tmp_path):
    path = tmp_path / "report.txt"
    path.write_text("First line\n\nexample.com\n", encoding="utf-8")

    records = ingest_file(path)

    assert [record.location for record in records] == [
        "line:1",
        "line:3",
    ]
    assert records[1].text == "example.com"
    assert records[1].source_file == "report.txt"


def test_csv_preserves_rows_and_columns(tmp_path):
    path = tmp_path / "traffic.csv"
    path.write_text(
        "source,destination\n192.0.2.1,example.com\n",
        encoding="utf-8",
    )

    records = ingest_file(path)

    assert records[0].location == "row:2/column:source"
    assert records[1].location == "row:2/column:destination"
    assert records[1].text == "example.com"


def test_nested_json_preserves_paths(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"events": [{"domain": "example.com"}]}),
        encoding="utf-8",
    )

    records = ingest_file(path)

    assert records[0].location == "$.events[0].domain"
    assert records[0].text == "example.com"


def test_unsupported_extension_is_rejected(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"not executed")

    with pytest.raises(ValueError, match="Unsupported"):
        ingest_file(path)


def test_oversized_file_is_rejected(tmp_path):
    path = tmp_path / "large.txt"
    path.write_text("123456", encoding="utf-8")

    with pytest.raises(ValueError, match="size limit"):
        ingest_file(path, max_file_bytes=5)


def test_malformed_json_is_rejected(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        ingest_file(path)