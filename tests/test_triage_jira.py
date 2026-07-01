"""Triage `.jira.json` artifact (build-next #5).

When --jira-project is given, the M3 triage emit writes a fourth artifact: a
per-kept-finding idempotent upsert bundle whose external keys match exactly
what report.py's live tool computes, so a re-run updates the same tickets.
"""

from __future__ import annotations

import json

from redteam import jira
from redteam.pipeline.emit import emit_report
from redteam.pipeline.models import Finding, TriageReport


def _report() -> TriageReport:
    return TriageReport(
        engagement_id="ENG-1",
        findings=[
            Finding(title="SQL injection", severity="critical", location="app/db.py:10"),
            Finding(title="XSS", severity="medium", location="web/view.py:3"),
        ],
    )


def test_emit_writes_jira_bundle_when_project_set(tmp_path) -> None:
    paths = emit_report(_report(), tmp_path, "ENG-1", jira_project="SEC")
    assert "jira" in paths and paths["jira"].exists()

    bundle = json.loads(paths["jira"].read_text())
    assert bundle["project"] == "SEC" and bundle["engagement_id"] == "ENG-1"
    assert len(bundle["issues"]) == 2

    first = bundle["issues"][0]
    # Key matches what the live report tool would compute -> re-run updates in place.
    assert first["external_key"] == jira.external_key("ENG-1", "SQL injection", "app/db.py:10")
    assert first["fields"]["project"] == {"key": "SEC"}
    assert first["fields"]["priority"] == {"name": "Highest"}
    assert 'labels = "' in first["jql"]


def test_no_jira_bundle_without_project(tmp_path) -> None:
    paths = emit_report(_report(), tmp_path, "ENG-1")
    assert "jira" not in paths
    assert not (tmp_path / "ENG-1.jira.json").exists()
    # The three standard artifacts are still emitted.
    assert paths["sarif"].exists() and paths["markdown"].exists() and paths["triage_json"].exists()


def test_cli_triage_jira_project_emits_bundle(tmp_path) -> None:
    from pathlib import Path

    from click.testing import CliRunner

    from redteam.cli import main

    fixture = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"
    out = tmp_path / "out"
    result = CliRunner().invoke(
        main, ["triage", str(fixture), "--out", str(out), "--jira-project", "SEC"]
    )
    assert result.exit_code == 0, result.output
    assert "jira:" in result.output
    assert (out / f"{fixture.stem}.jira.json").exists()


def test_cli_triage_rejects_bad_jira_project(tmp_path) -> None:
    from pathlib import Path

    from click.testing import CliRunner

    from redteam.cli import main

    fixture = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"
    out = tmp_path / "out"
    result = CliRunner().invoke(
        main, ["triage", str(fixture), "--out", str(out), "--jira-project", 'A" OR labels = "x']
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert not (out / f"{fixture.stem}.jira.json").exists()
