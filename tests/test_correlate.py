
import pytest

from src.correlate import (
    find_shared_indicators,
    rank_related_samples,
)
from src.database import ThreatGraphDB


def add_test_occurrence(db, sample_id, ioc_type, value):
    """Insert test evidence using the real database API."""
    with db.transaction() as conn:
        db.add_sample(sample_id, conn=conn)

        import_id, _ = db.add_import(
            sample_id=sample_id,
            source_file=f"{sample_id}.txt",
            file_sha256=(sample_id.encode().hex() + "0" * 64)[:64],
            conn=conn,
        )

        db.add_occurrence(
            sample_id=sample_id,
            import_id=import_id,
            ioc_type=ioc_type,
            canonical_value=value,
            original_text=value,
            source_file=f"{sample_id}.txt",
            file_type="txt",
            location="line:1",
            extraction_method="test",
            conn=conn,
        )


@pytest.fixture
def db(tmp_path):
    return ThreatGraphDB(tmp_path / "correlation.db")


def test_finds_indicator_shared_by_two_samples(db):
    add_test_occurrence(db, "A", "ipv4", "192.0.2.10")
    add_test_occurrence(db, "B", "ipv4", "192.0.2.10")
    add_test_occurrence(db, "C", "domain", "unique.example")

    results = find_shared_indicators(db)

    assert results == [
        {
            "ioc_type": "ipv4",
            "canonical_value": "192.0.2.10",
            "sample_ids": ["A", "B"],
            "sample_count": 2,
            "occurrence_counts": {"A": 1, "B": 1},
        }
    ]


def test_repeated_occurrences_do_not_inflate_pair_score(db):
    for _ in range(4):
        add_test_occurrence(db, "A", "ipv4", "192.0.2.10")

    add_test_occurrence(db, "B", "ipv4", "192.0.2.10")

    results = rank_related_samples(db)

    assert len(results) == 1
    assert results[0]["shared_indicator_count"] == 1
    assert results[0]["shared_indicators"] == [
        {
            "ioc_type": "ipv4",
            "canonical_value": "192.0.2.10",
        }
    ]


def test_ranks_pairs_by_distinct_shared_indicators(db):
    for value in ("192.0.2.10", "192.0.2.11"):
        add_test_occurrence(db, "A", "ipv4", value)
        add_test_occurrence(db, "B", "ipv4", value)

    add_test_occurrence(db, "A", "domain", "shared.example")
    add_test_occurrence(db, "B", "domain", "shared.example")
    add_test_occurrence(db, "C", "ipv4", "192.0.2.10")

    results = rank_related_samples(db)

    assert results[0]["sample_a"] == "A"
    assert results[0]["sample_b"] == "B"
    assert results[0]["shared_indicator_count"] == 3
    assert results[1]["shared_indicator_count"] == 1


def test_can_filter_correlations_to_one_sample(db):
    add_test_occurrence(db, "A", "domain", "shared.example")
    add_test_occurrence(db, "B", "domain", "shared.example")
    add_test_occurrence(db, "C", "domain", "shared.example")

    results = rank_related_samples(db, sample_id="A")

    assert len(results) == 2
    assert all("A" in (r["sample_a"], r["sample_b"]) for r in results)


def test_no_shared_indicators_returns_empty_list(db):
    add_test_occurrence(db, "A", "ipv4", "192.0.2.10")
    add_test_occurrence(db, "B", "ipv4", "192.0.2.11")

    assert find_shared_indicators(db) == []
    assert rank_related_samples(db) == []


def test_invalid_thresholds_are_rejected(db):
    with pytest.raises(ValueError):
        find_shared_indicators(db, min_samples=1)

    with pytest.raises(ValueError):
        rank_related_samples(db, min_shared=0)
