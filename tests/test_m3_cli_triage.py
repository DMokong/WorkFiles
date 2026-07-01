"""M3 CLI — `redteam triage` deterministic path over a ledger."""

from __future__ import annotations

import shutil
from pathlib import Path

from click.testing import CliRunner

from redteam.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"


def test_triage_deterministic_emits_artifacts(tmp_path):
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(FIXTURE), "--out", str(out)])
    assert result.exit_code == 0, result.output
    # Summary reports kept / dropped / chains.
    assert "kept" in result.output.lower()
    stem = FIXTURE.stem
    assert (out / f"{stem}.triaged.sarif").exists()
    assert (out / f"{stem}.report.md").exists()
    assert (out / f"{stem}.triage.json").exists()


def test_triage_defaults_out_to_ledger_parent(tmp_path):
    ledger = tmp_path / "ENG-COPY.jsonl"
    shutil.copy(FIXTURE, ledger)
    result = CliRunner().invoke(main, ["triage", str(ledger)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "ENG-COPY.triaged.sarif").exists()
    assert (tmp_path / "ENG-COPY.report.md").exists()


def test_triage_missing_ledger_exits_clean():
    result = CliRunner().invoke(main, ["triage", "/no/such/ledger.jsonl"])
    assert result.exit_code != 0
    # A usage error, not an unhandled traceback.
    assert "Traceback" not in result.output


_BACKEND_VARS = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_MANTLE",
)


def test_triage_verify_without_backend_exits_clean(tmp_path, monkeypatch):
    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(FIXTURE), "--out", str(out), "--verify"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "backend" in result.output.lower()
    # Deterministic artifacts must NOT be written when the gate refuses.
    assert not out.exists()


def test_triage_verify_with_backend_and_mocked_model(tmp_path, monkeypatch):
    import json

    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def fake_ask(system, user, *, model=None):
        return "VERDICT: TRUE_POSITIVE (confidence: 9/10) — confirmed"

    monkeypatch.setattr("redteam.pipeline.llm.ask", fake_ask)

    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(FIXTURE), "--out", str(out), "--verify"])
    assert result.exit_code == 0, result.output
    data = json.loads((out / f"{FIXTURE.stem}.triage.json").read_text())
    assert data["metrics"]["verified"] is True
    assert all(f["verdict"] == "TRUE_POSITIVE" for f in data["findings"])
