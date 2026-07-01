"""M3 emit.py — refined SARIF + markdown + triage.json."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.pipeline import emit, stages
from redteam.pipeline.load import findings_from_ledger
from redteam.pipeline.models import TriageReport

FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"


def _report():
    engagement_id, findings = findings_from_ledger(FIXTURE)
    return stages.run_triage(findings, engagement_id=engagement_id, assets_root=None)


def test_emit_writes_three_artifacts(tmp_path):
    report = _report()
    paths = emit.emit_report(report, tmp_path, "ENG-SYNTH-01")
    assert paths["sarif"] == tmp_path / "ENG-SYNTH-01.triaged.sarif"
    assert paths["markdown"] == tmp_path / "ENG-SYNTH-01.report.md"
    assert paths["triage_json"] == tmp_path / "ENG-SYNTH-01.triage.json"
    for p in paths.values():
        assert p.exists()


def test_sarif_shape_levels_and_properties(tmp_path):
    report = _report()
    paths = emit.emit_report(report, tmp_path, "ENG-SYNTH-01")
    doc = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    results = run["results"]
    assert len(results) == len(report.findings)

    sqli = next(r for r in results if r["ruleId"] == "CWE-89")
    assert sqli["level"] == "error"  # critical -> error (reused report.py map)
    props = sqli["properties"]
    assert props["cwe"] == "CWE-89" and props["cweName"]
    assert props["cvssScore"] == 9.3 and props["cvssRating"] == "Critical"
    assert props["severity"] == "critical"
    # SQLi finding had a near-duplicate collapsed into it -> relatedLocations.
    assert sqli["relatedLocations"] and sqli["relatedLocations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == "app/users.py"


def test_sarif_has_cwe_taxonomy_block(tmp_path):
    report = _report()
    paths = emit.emit_report(report, tmp_path, "ENG-SYNTH-01")
    run = json.loads(paths["sarif"].read_text(encoding="utf-8"))["runs"][0]
    taxonomies = run["taxonomies"]
    cwe_tax = next(t for t in taxonomies if t["name"] == "CWE")
    taxa_ids = {t["id"] for t in cwe_tax["taxa"]}
    assert "CWE-89" in taxa_ids and "CWE-918" in taxa_ids


def test_markdown_report_structure(tmp_path):
    report = _report()
    paths = emit.emit_report(report, tmp_path, "ENG-SYNTH-01")
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "ENG-SYNTH-01" in md
    assert "SQL injection" in md
    assert "CWE-89" in md
    # Dropped appendix names the drop reasons.
    assert "NO_EVIDENCE" in md and "DUPLICATE" in md


def test_triage_json_roundtrips(tmp_path):
    report = _report()
    paths = emit.emit_report(report, tmp_path, "ENG-SYNTH-01")
    loaded = TriageReport.model_validate_json(paths["triage_json"].read_text(encoding="utf-8"))
    assert loaded.engagement_id == "ENG-SYNTH-01"
    assert len(loaded.findings) == len(report.findings)
