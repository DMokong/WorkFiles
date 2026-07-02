"""Environmental CVSS in enrich + offensive-priority scoring (M3 v-next).

enrich() now also computes an environmental CVSS score (base when no
environmental inputs; raised/lowered by security requirements + modified base
metrics). A new prioritize() step, run after chains, blends environmental CVSS +
exploitability + verify verdict + chain membership into a 0..100 priority score
and a P1..P4 tier so an operator can sort by offensive value.
"""

from __future__ import annotations

from redteam.pipeline import cvss
from redteam.pipeline.models import Chain, Finding
from redteam.pipeline.stages import enrich, prioritize, run_triage

_NET_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # base 9.8
_LOW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # base 5.3


# ---- enrich: environmental --------------------------------------------------


def test_enrich_sets_environmental_equal_to_base_without_requirements():
    f = Finding(title="SQLi", severity="high", location="a.py:1", cvss_vector=_NET_CRIT)
    enrich([f])
    assert f.cvss_score == 9.8
    assert f.cvss_environmental_score == 9.8 and f.cvss_environmental_rating == "Critical"


def test_enrich_applies_security_requirements():
    f = Finding(title="x", severity="medium", location="a.py:1", cvss_vector=_LOW)
    enrich([f], security_requirements={"CR": "H"})
    assert f.cvss_score == 5.3  # base unchanged
    assert f.cvss_environmental_score == 6.1  # raised by the confidentiality requirement


def test_enrich_no_vector_environmental_falls_back_to_band():
    f = Finding(title="x", severity="high", location="a.py:1")  # no vector
    enrich([f])
    assert f.cvss_source == "severity_band"
    assert f.cvss_environmental_score == f.cvss_score
    assert f.cvss_environmental_rating == f.cvss_rating


def test_enrich_environmental_falls_back_to_base_on_garbage_modified_metric():
    # A valid base vector with an unparseable MODIFIED metric still gets an env
    # score (== base), not a bare None shown as "-".
    f = Finding(title="x", severity="high", location="a.py:1", cvss_vector=_NET_CRIT + "/MAV:Z")
    enrich([f])
    assert f.cvss_score == 9.8
    assert f.cvss_environmental_score == 9.8 and f.cvss_environmental_rating == "Critical"


# ---- prioritize -------------------------------------------------------------


def _enriched(vector=None, severity="medium", verdict=None, confidence=None):
    f = Finding(title="f", severity=severity, location="a.py:1", cvss_vector=vector,
                verdict=verdict, verdict_confidence=confidence)
    enrich([f])
    return f


def test_prioritize_network_verified_chain_finding_is_p1():
    f = _enriched(vector=_NET_CRIT, severity="critical", verdict="TRUE_POSITIVE", confidence=9)
    prioritize([f], [Chain(title="c", steps=[0], severity="critical")])
    assert f.priority_score == 100 and f.priority_rating == "P1"  # 98 + exploit + verify + chain, clamped


def test_prioritize_low_isolated_unverified_is_low_tier():
    f = _enriched(vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", severity="low")
    prioritize([f], [])
    assert f.priority_score < 40 and f.priority_rating == "P4"


def test_prioritize_chain_membership_raises_priority():
    a = _enriched(vector=_LOW)
    b = _enriched(vector=_LOW)
    prioritize([a, b], [Chain(title="c", steps=[0], severity="medium")])
    assert a.priority_score > b.priority_score  # a is a chain step, b is not


def test_prioritize_uses_zero_environmental_not_base():
    # A legitimate environmental score of 0.0 (impact zeroed by MC/MI/MA:N) must
    # drive priority, NOT silently fall through to the base score.
    f = _enriched(vector=_NET_CRIT + "/MC:N/MI:N/MA:N")
    assert f.cvss_environmental_score == 0.0
    prioritize([f], [])
    # base contribution 0; only the exploitability bonus (AV:N+AC:L+PR:N+UI:N=15).
    assert f.priority_score == 15


def test_prioritize_clamps_and_tiers_are_ordered():
    f = _enriched(vector=_NET_CRIT, severity="critical", verdict="TRUE_POSITIVE", confidence=10)
    prioritize([f], [Chain(title="c", steps=[0], severity="critical")])
    assert 0 <= f.priority_score <= 100


# ---- run_triage integration -------------------------------------------------


def test_run_triage_populates_priority_and_environmental():
    findings = [
        Finding(title="SQL injection", severity="critical", location="app/db.py:10", cvss_vector=_NET_CRIT,
                evidence={"snippet": "query = f'... {user}'"}),
    ]
    report = run_triage(findings, engagement_id="ENG-1", security_requirements={"CR": "H", "IR": "H"})
    f = report.findings[0]
    assert f.cvss_environmental_score is not None
    assert f.priority_score is not None and f.priority_rating in ("P1", "P2", "P3", "P4")


def test_metrics_public_helper_exposes_parsed_vector():
    assert cvss.metrics(_NET_CRIT)["AV"] == "N"
    assert cvss.metrics("garbage") is None


# ---- CLI --security-requirements parsing ------------------------------------


def test_emit_surfaces_priority_and_environmental(tmp_path):
    import json

    from redteam.pipeline.emit import emit_report
    from redteam.pipeline.models import TriageReport

    f = _enriched(vector=_NET_CRIT, severity="critical", verdict="TRUE_POSITIVE", confidence=9)
    prioritize([f], [])
    paths = emit_report(TriageReport(engagement_id="ENG-1", findings=[f]), tmp_path, "ENG-1")

    props = json.loads(paths["sarif"].read_text())["runs"][0]["results"][0]["properties"]
    assert props["priorityScore"] == f.priority_score
    assert props["priorityRating"] in ("P1", "P2", "P3", "P4")
    assert props["cvssEnvironmentalScore"] == f.cvss_environmental_score
    assert "Priority" in paths["markdown"].read_text()


def test_parse_security_requirements_ok():
    from redteam.cli import _parse_security_requirements

    assert _parse_security_requirements("CR:H,IR:M/AR:L") == {"CR": "H", "IR": "M", "AR": "L"}
    assert _parse_security_requirements("cr:h") == {"CR": "H"}


def test_parse_security_requirements_rejects_bad():
    import pytest

    from redteam.cli import _parse_security_requirements

    for bad in ["CR:Z", "XX:H", "CR", "CR:H;IR:M"]:
        with pytest.raises(ValueError):
            _parse_security_requirements(bad)


def test_cli_triage_accepts_security_requirements(tmp_path):
    from pathlib import Path

    from click.testing import CliRunner

    from redteam.cli import main

    fixture = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"
    out = tmp_path / "out"
    ok = CliRunner().invoke(main, ["triage", str(fixture), "--out", str(out), "--security-requirements", "CR:H,IR:H"])
    assert ok.exit_code == 0, ok.output
    bad = CliRunner().invoke(main, ["triage", str(fixture), "--out", str(out), "--security-requirements", "CR:Z"])
    assert bad.exit_code != 0 and "Traceback" not in bad.output
