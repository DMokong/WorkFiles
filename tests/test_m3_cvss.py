"""M3 cvss.py — CVSS 3.1 base score from a vector + severity-band fallback."""

from __future__ import annotations

import pytest

from redteam.pipeline import cvss


@pytest.mark.parametrize(
    "vector, score, rating",
    [
        # Canonical FIRST.org worked examples.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
    ],
)
def test_base_score_from_vector(vector, score, rating):
    got = cvss.base_score(vector)
    assert got is not None
    assert got == (pytest.approx(score), rating)


def test_base_score_none_on_garbage_or_incomplete():
    assert cvss.base_score("not a vector") is None
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L") is None  # missing required metrics
    assert cvss.base_score("") is None
    assert cvss.base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None  # bad value


@pytest.mark.parametrize(
    "score, rating",
    [
        (0.0, "None"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_rating_bands(score, rating):
    assert cvss.rating_for(score) == rating


@pytest.mark.parametrize(
    "severity, score, rating",
    [
        ("critical", 9.3, "Critical"),
        ("high", 7.8, "High"),
        ("medium", 5.5, "Medium"),
        ("low", 2.5, "Low"),
        ("info", 0.0, "None"),
    ],
)
def test_severity_band_fallback(severity, score, rating):
    assert cvss.severity_band(severity) == (pytest.approx(score), rating)


def test_severity_band_unknown_is_none_band():
    assert cvss.severity_band("bogus") == (pytest.approx(0.0), "None")
