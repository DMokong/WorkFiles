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


# --- environmental CVSS 3.1 (M3 v-next) --------------------------------------

_BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # base 9.8


def test_environmental_equals_base_for_scope_unchanged_no_env_inputs():
    # Scope-UNCHANGED, no environmental inputs -> env == base.
    for v in [
        _BASE,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # base 7.8
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # base 5.3
    ]:
        assert cvss.environmental_score(v) == cvss.base_score(v)


def test_environmental_scope_changed_may_differ_from_base_by_spec():
    # CVSS 3.1's environmental modified-impact formula genuinely differs from the
    # base impact formula for scope-CHANGED vectors, so even with NO environmental
    # inputs the env score can differ from base. This is spec-correct, not a bug
    # (cross-checked against the RedHat `cvss` library).
    v = "CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H"
    assert cvss.base_score(v)[0] == pytest.approx(6.9)
    assert cvss.environmental_score(v)[0] == pytest.approx(7.0)


def test_environmental_security_requirement_raises_low_impact():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # base 5.3
    assert cvss.base_score(v)[0] == pytest.approx(5.3)
    env = cvss.environmental_score(v, requirements={"CR": "H"})
    assert env[0] == pytest.approx(6.1) and env[1] == "Medium"
    assert env[0] > cvss.base_score(v)[0]


def test_environmental_modified_base_metric_lowers_score():
    # Physical access requirement (MAV:P) cuts exploitability well below base 9.8.
    env = cvss.environmental_score(_BASE + "/MAV:P")
    assert env[0] == pytest.approx(6.8)
    assert env[0] < cvss.base_score(_BASE)[0]


def test_environmental_requirements_are_monotonic():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    lo = cvss.environmental_score(v, requirements={"CR": "L", "IR": "L", "AR": "L"})[0]
    md = cvss.environmental_score(v, requirements={"CR": "M", "IR": "M", "AR": "M"})[0]
    hi = cvss.environmental_score(v, requirements={"CR": "H", "IR": "H", "AR": "H"})[0]
    assert lo <= md <= hi
    assert md == pytest.approx(cvss.base_score(v)[0])  # M == Not Defined == base


def test_environmental_none_on_garbage():
    assert cvss.environmental_score("not a vector") is None
    assert cvss.environmental_score("CVSS:3.1/AV:N/AC:L") is None
