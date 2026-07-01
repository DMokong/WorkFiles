"""M3 stages.py — prefilter, dedup, enrich, deterministic run_triage."""

from __future__ import annotations

from pathlib import Path

from redteam.pipeline import stages
from redteam.pipeline.load import findings_from_ledger
from redteam.pipeline.models import Finding

FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"


def _f(**kw) -> Finding:
    kw.setdefault("title", "t")
    kw.setdefault("severity", "high")
    return Finding(**kw)


# --- prefilter ---------------------------------------------------------------


def test_prefilter_drops_no_evidence():
    f = _f(description="", evidence={}, location="a.py:1")
    kept, dropped = stages.prefilter([f], assets_root=None)
    assert kept == []
    assert [d.reason for d in dropped] == ["NO_EVIDENCE"]


def test_prefilter_drops_bad_location():
    kept, dropped = stages.prefilter(
        [_f(description="real bug", location=None), _f(description="real", location="nonsense")],
        assets_root=None,
    )
    assert kept == []
    assert [d.reason for d in dropped] == ["BAD_LOCATION", "BAD_LOCATION"]


def test_prefilter_keeps_valid_without_assets_root():
    f = _f(description="real bug", location="a.py:1")
    kept, dropped = stages.prefilter([f], assets_root=None)
    assert kept == [f] and dropped == []


def test_prefilter_file_not_found_under_assets(tmp_path):
    (tmp_path / "exists.py").write_text("x = 1\n", encoding="utf-8")
    present = _f(description="d", location="exists.py:1")
    absent = _f(description="d", location="missing.py:1")
    kept, dropped = stages.prefilter([present, absent], assets_root=tmp_path)
    assert kept == [present]
    assert [d.reason for d in dropped] == ["FILE_NOT_FOUND"]


def test_prefilter_containment_blocks_escape(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "secret.py").write_text("secret\n", encoding="utf-8")  # outside root
    escaping = _f(description="d", location="../secret.py:1")
    kept, dropped = stages.prefilter([escaping], assets_root=root)
    assert kept == []
    assert dropped[0].reason == "FILE_NOT_FOUND"  # exists on disk, but outside scope


# --- dedup -------------------------------------------------------------------


def test_dedup_collapses_near_duplicate():
    a = _f(title="SQL injection reachable", severity="critical", description="d", location="app/users.py:21")
    b = _f(title="SQL injection reachable", severity="critical", description="d", location="app/users.py:24")
    kept, dropped = stages.dedup([a, b])
    assert kept == [a]  # first is canonical
    assert [d.reason for d in dropped] == ["DUPLICATE"]
    assert a.duplicates and a.duplicates[0].file == "app/users.py" and a.duplicates[0].line == 24


def test_dedup_keeps_distant_same_class():
    a = _f(title="SQL injection", severity="critical", description="d", location="app/users.py:21")
    b = _f(title="SQL injection", severity="critical", description="d", location="app/users.py:80")
    kept, dropped = stages.dedup([a, b])
    assert len(kept) == 2 and dropped == []


def test_dedup_keeps_different_class_same_line():
    a = _f(title="SQL injection", description="d", location="app/x.py:10")
    b = _f(title="SSRF issue", description="d", location="app/x.py:10")
    kept, _ = stages.dedup([a, b])
    assert len(kept) == 2


# --- enrich ------------------------------------------------------------------


def test_enrich_severity_band_when_no_vector():
    f = _f(title="SQL injection in get_user", severity="critical", description="d", location="a.py:1")
    stages.enrich([f])
    assert f.vuln_class == "sqli"
    assert f.cwe == "CWE-89" and f.cwe_name
    assert f.cvss_source == "severity_band"
    assert f.cvss_score == 9.3 and f.cvss_rating == "Critical"


def test_enrich_uses_vector_when_present():
    f = _f(title="SQL injection", severity="low", description="d", location="a.py:1")
    f.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    stages.enrich([f])
    assert f.cvss_source == "vector"
    assert f.cvss_score == 9.8 and f.cvss_rating == "Critical"


def test_enrich_falls_back_when_vector_garbage():
    f = _f(title="SSRF", severity="high", description="d", location="a.py:1")
    f.cvss_vector = "totally-bogus"
    stages.enrich([f])
    assert f.cvss_source == "severity_band"
    assert f.cvss_score == 7.8 and f.cwe == "CWE-918"


# --- run_triage (deterministic) ---------------------------------------------


def test_run_triage_over_fixture_is_deterministic():
    engagement_id, findings = findings_from_ledger(FIXTURE)
    report = stages.run_triage(findings, engagement_id=engagement_id, assets_root=None)
    assert report.engagement_id == "ENG-SYNTH-01"
    # 6 recorded -> 1 NO_EVIDENCE dropped, 1 DUPLICATE collapsed -> 4 kept.
    assert len(report.findings) == 4
    reasons = sorted(d.reason for d in report.dropped)
    assert reasons == ["DUPLICATE", "NO_EVIDENCE"]
    # Every kept finding is CWE + CVSS enriched.
    assert all(f.cwe and f.cvss_score is not None and f.cvss_rating for f in report.findings)
    assert report.metrics["kept"] == 4 and report.metrics["input"] == 6
    assert report.chains == [] and report.degraded is False
