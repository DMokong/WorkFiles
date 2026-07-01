"""M3 models.py — tolerant pydantic finding model + canonical dedup key."""

from __future__ import annotations

from redteam.pipeline.models import (
    Chain,
    DroppedFinding,
    DupLocation,
    Finding,
    TriageReport,
)


def test_minimal_finding_defaults():
    f = Finding(title="t", severity="high")
    assert f.severity == "high"
    assert f.description == ""
    assert f.evidence == {}
    assert f.location is None
    assert f.duplicates == []
    assert f.verdict is None


def test_severity_is_coerced_not_crashed():
    assert Finding(title="t", severity="CRITICAL").severity == "critical"
    assert Finding(title="t", severity=" High ").severity == "high"
    # An unknown/garbage severity degrades to the safest band rather than raising.
    assert Finding(title="t", severity="sev5").severity == "info"
    assert Finding(title="t", severity="").severity == "info"


def test_malformed_field_types_are_tolerated():
    # A hostile/garbage finding dict must never crash construction.
    f = Finding.model_validate(
        {
            "title": 123,
            "severity": ["high"],
            "description": None,
            "evidence": "not-a-dict",
            "location": 42,
        }
    )
    assert isinstance(f.title, str) and f.title
    assert f.description == ""
    assert f.evidence == {}
    assert f.severity == "info"  # unrecognised -> safe band


def test_parsed_location_file_and_line():
    f = Finding(title="t", severity="high", location="app/users.py:21")
    assert f.parsed_location() == ("app/users.py", 21, 21)
    assert f.line_no == 21


def test_parsed_location_range():
    f = Finding(title="t", severity="high", location="app/x.py:16-18")
    assert f.parsed_location() == ("app/x.py", 16, 18)
    assert f.line_no == 16


def test_parsed_location_none_when_absent_or_malformed():
    assert Finding(title="t", severity="high").parsed_location() is None
    assert Finding(title="t", severity="high", location="no-colon-here").parsed_location() is None


def test_canonical_key_uses_derived_vuln_class():
    f = Finding(
        title="SQL injection in get_user via f-string",
        severity="critical",
        location="app/users.py:21",
    )
    assert f.canonical_key() == ("app/users.py", 2, "sqli")


def test_canonical_key_prefers_explicit_vuln_class():
    f = Finding(
        title="nondescript",
        severity="high",
        location="app/x.py:16-18",
        vuln_class="ssrf",
    )
    assert f.canonical_key() == ("app/x.py", 1, "ssrf")


def test_dedup_pair_shares_canonical_key():
    a = Finding(title="SQL injection reachable", severity="critical", location="app/users.py:21")
    b = Finding(title="SQL injection reachable", severity="critical", location="app/users.py:24")
    assert a.canonical_key() == b.canonical_key()


def test_dup_location_and_chain_and_dropped_and_report():
    dup = DupLocation(file="app/users.py", line=24)
    assert dup.file == "app/users.py" and dup.line == 24

    chain = Chain(title="path", steps=[0, 1], severity="high")
    assert chain.steps == [0, 1]

    dropped = DroppedFinding(
        finding=Finding(title="t", severity="low"), reason="NO_EVIDENCE"
    )
    assert dropped.reason == "NO_EVIDENCE"

    report = TriageReport(engagement_id="ENG-1", findings=[], dropped=[], chains=[], metrics={})
    assert report.degraded is False and report.engagement_id == "ENG-1"
