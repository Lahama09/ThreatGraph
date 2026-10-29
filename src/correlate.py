
"""Explainable IOC correlation across ThreatGraph samples."""

from collections import defaultdict
from itertools import combinations


def _indicator_sample_rows(db):
    """Return one row per indicator per sample, with occurrence counts."""
    with db._connection() as conn:
        return conn.execute(
            """
            SELECT
                i.ioc_type,
                i.canonical_value,
                e.sample_id,
                COUNT(*) AS occurrence_count
            FROM evidence_occurrences AS e
            JOIN indicators AS i
                ON i.indicator_id = e.indicator_id
            GROUP BY
                i.indicator_id,
                i.ioc_type,
                i.canonical_value,
                e.sample_id
            ORDER BY
                i.ioc_type,
                i.canonical_value,
                e.sample_id
            """
        ).fetchall()


def find_shared_indicators(db, min_samples=2):
    """Find indicators observed in at least min_samples distinct samples.

    Each result includes the IOC type, canonical value, sample IDs,
    and occurrence count within each sample.
    """
    if min_samples < 2:
        raise ValueError("min_samples must be at least 2")

    grouped = defaultdict(dict)

    for row in _indicator_sample_rows(db):
        key = (row["ioc_type"], row["canonical_value"])
        grouped[key][row["sample_id"]] = row["occurrence_count"]

    results = []

    for (ioc_type, canonical_value), sample_counts in grouped.items():
        if len(sample_counts) < min_samples:
            continue

        results.append(
            {
                "ioc_type": ioc_type,
                "canonical_value": canonical_value,
                "sample_ids": sorted(sample_counts),
                "sample_count": len(sample_counts),
                "occurrence_counts": dict(sorted(sample_counts.items())),
            }
        )

    return results


def rank_related_samples(db, sample_id=None, min_shared=1):
    """Rank sample pairs by the number of distinct shared indicators.

    If sample_id is provided, return only pairs involving that sample.
    Shared indicator details are included so every score is explainable.
    """
    if min_shared < 1:
        raise ValueError("min_shared must be at least 1")

    indicator_samples = defaultdict(set)

    for row in _indicator_sample_rows(db):
        key = (row["ioc_type"], row["canonical_value"])
        indicator_samples[key].add(row["sample_id"])

    pair_indicators = defaultdict(list)

    for (ioc_type, canonical_value), samples in indicator_samples.items():
        if len(samples) < 2:
            continue

        for sample_a, sample_b in combinations(sorted(samples), 2):
            if sample_id is not None and sample_id not in {
                sample_a, sample_b
            }:
                continue

            pair_indicators[(sample_a, sample_b)].append(
                {
                    "ioc_type": ioc_type,
                    "canonical_value": canonical_value,
                }
            )

    results = []

    for (sample_a, sample_b), indicators in pair_indicators.items():
        indicators.sort(
            key=lambda item: (item["ioc_type"], item["canonical_value"])
        )

        if len(indicators) < min_shared:
            continue

        results.append(
            {
                "sample_a": sample_a,
                "sample_b": sample_b,
                "shared_indicator_count": len(indicators),
                "shared_indicators": indicators,
            }
        )

    return sorted(
        results,
        key=lambda item: (
            -item["shared_indicator_count"],
            item["sample_a"],
            item["sample_b"],
        ),
    )