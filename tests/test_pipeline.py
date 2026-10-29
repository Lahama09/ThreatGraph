
import json

from src.database import ThreatGraphDB
from src.pipeline import import_evidence


def test_txt_import_stores_iocs_and_provenance(tmp_path):
    evidence = tmp_path / "analysis.txt"
    evidence.write_text(
        "Connection to 192.0.2.10\n"
        "Repeated connection to 192.0.2.10\n",
        encoding="utf-8",
    )
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    result = import_evidence(db, "sample-001", evidence)

    assert result.skipped_duplicate is False
    assert result.occurrences_added == 2
    assert db.count("samples") == 1
    assert db.count("imports") == 1
    assert db.count("indicators") == 1
    assert db.count("evidence_occurrences") == 2

    rows = db.get_indicators_for_sample("sample-001")
    assert [row["location"] for row in rows] == ["line:1", "line:2"]
    assert all(row["canonical_value"] == "192.0.2.10" for row in rows)
    assert all(row["source_file"] == "analysis.txt" for row in rows)


def test_duplicate_import_is_skipped(tmp_path):
    evidence = tmp_path / "analysis.log"
    evidence.write_text("Suspicious host example.com\n", encoding="utf-8")
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    first = import_evidence(db, "sample-001", evidence)
    second = import_evidence(db, "sample-001", evidence)

    assert first.skipped_duplicate is False
    assert second.skipped_duplicate is True
    assert second.import_id == first.import_id
    assert second.occurrences_added == 0
    assert db.count("imports") == 1
    assert db.count("evidence_occurrences") == first.occurrences_added


def test_same_file_can_be_imported_for_another_sample(tmp_path):
    evidence = tmp_path / "shared.txt"
    evidence.write_text("Observed 192.0.2.20\n", encoding="utf-8")
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    first = import_evidence(db, "sample-A", evidence)
    second = import_evidence(db, "sample-B", evidence)

    assert first.skipped_duplicate is False
    assert second.skipped_duplicate is False
    assert db.count("samples") == 2
    assert db.count("imports") == 2


def test_csv_import_preserves_row_and_column(tmp_path):
    evidence = tmp_path / "events.csv"
    evidence.write_text(
        "event,details\n"
        'network,"Contacted example.com"\n',
        encoding="utf-8",
    )
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    result = import_evidence(db, "sample-csv", evidence)

    assert result.occurrences_added >= 1
    rows = db.get_indicators_for_sample("sample-csv")
    domain_rows = [
        row for row in rows if row["canonical_value"] == "example.com"
    ]
    assert len(domain_rows) == 1
    assert domain_rows[0]["location"] == "row:2/column:details"


def test_invalid_json_does_not_create_database_records(tmp_path):
    evidence = tmp_path / "broken.json"
    evidence.write_text("{invalid json", encoding="utf-8")
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    try:
        import_evidence(db, "sample-bad", evidence)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected invalid JSON to raise ValueError")

    assert db.count("samples") == 0
    assert db.count("imports") == 0
    assert db.count("indicators") == 0
    assert db.count("evidence_occurrences") == 0


def test_json_import_preserves_json_path(tmp_path):
    evidence = tmp_path / "events.json"
    evidence.write_text(
        json.dumps({"network": {"destination": "192.0.2.30"}}),
        encoding="utf-8",
    )
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    import_evidence(db, "sample-json", evidence)

    rows = db.get_indicators_for_sample("sample-json")
    ip_rows = [
        row for row in rows if row["canonical_value"] == "192.0.2.30"
    ]

    assert len(ip_rows) == 1
    assert ip_rows[0]["location"] == "$.network.destination"
