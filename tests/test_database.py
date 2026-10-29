
import hashlib

import pytest

from src.database import ThreatGraphDB, calculate_sha256


def setup_import(db, sample_id="S001"):
    db.add_sample(sample_id, "Test sample")
    return db.add_import(
        sample_id,
        "report.txt",
        "a" * 64,
    )


def test_database_creates_all_four_tables(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    assert db.count("samples") == 0
    assert db.count("indicators") == 0
    assert db.count("imports") == 0
    assert db.count("evidence_occurrences") == 0


def test_duplicate_indicators_are_stored_once(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")
    import_id, created = setup_import(db)

    assert created

    with db.transaction() as conn:
        for original in ("EXAMPLE.COM", "example.com"):
            db.add_occurrence(
                sample_id="S001",
                import_id=import_id,
                ioc_type="domain",
                canonical_value="example.com",
                original_text=original,
                source_file="report.txt",
                file_type="txt",
                location="line:1",
                extraction_method="domain",
                conn=conn,
            )

    assert db.count("indicators") == 1
    assert db.count("evidence_occurrences") == 2


def test_duplicate_import_is_detected(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")
    db.add_sample("S001")

    first_id, first_created = db.add_import(
        "S001", "report.txt", "b" * 64
    )
    second_id, second_created = db.add_import(
        "S001", "renamed.txt", "b" * 64
    )

    assert first_created is True
    assert second_created is False
    assert first_id == second_id
    assert db.count("imports") == 1


def test_same_file_can_be_imported_for_another_sample(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")
    db.add_sample("S001")
    db.add_sample("S002")

    _, first_created = db.add_import(
        "S001", "report.txt", "c" * 64
    )
    _, second_created = db.add_import(
        "S002", "report.txt", "c" * 64
    )

    assert first_created is True
    assert second_created is True
    assert db.count("imports") == 2


def test_transaction_rolls_back_on_error(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            db.add_sample("S001", conn=conn)
            raise RuntimeError("Simulated import failure")

    assert db.count("samples") == 0


def test_foreign_keys_reject_missing_sample(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    with pytest.raises(Exception):
        db.add_import("MISSING", "report.txt", "d" * 64)

    assert db.count("imports") == 0


def test_sha256_calculation(tmp_path):
    path = tmp_path / "evidence.txt"
    path.write_bytes(b"ThreatGraph test")

    expected = hashlib.sha256(b"ThreatGraph test").hexdigest()

    assert calculate_sha256(path) == expected


def test_invalid_table_name_is_rejected(tmp_path):
    db = ThreatGraphDB(tmp_path / "threatgraph.db")

    with pytest.raises(ValueError):
        db.count("users")
