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


def test_triage_verify_no_backend_and_no_cli_refuses(tmp_path, monkeypatch):
    # Refuse the model stages only when there is neither an env backend NOR a
    # usable claude CLI to authenticate through.
    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: None)
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(FIXTURE), "--out", str(out), "--verify"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "backend" in result.output.lower()
    # Deterministic artifacts must NOT be written when the gate refuses.
    assert not out.exists()


def test_triage_verify_allowed_with_logged_in_cli(tmp_path, monkeypatch):
    # No env backend, but a present claude CLI (login/session auth, as on the dev
    # host) satisfies the gate — like the `run` command, which lets the CLI auth.
    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: "/usr/local/bin/claude")

    async def fake_ask(system, user, *, model=None):
        return "VERDICT: TRUE_POSITIVE (confidence: 8/10) — reachable"

    monkeypatch.setattr("redteam.pipeline.llm.ask", fake_ask)
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(FIXTURE), "--out", str(out), "--verify"])
    assert result.exit_code == 0, result.output
    import json

    data = json.loads((out / f"{FIXTURE.stem}.triage.json").read_text())
    assert data["metrics"]["verified"] is True


def test_model_stage_ready_logic(monkeypatch):
    from redteam import preflight

    env_key = {"ANTHROPIC_API_KEY": "x"}
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: None)
    assert preflight.model_stage_ready(env_key)[0] is True  # env backend wins
    assert preflight.model_stage_ready({})[0] is False  # no backend, no CLI
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: "/x/claude")
    assert preflight.model_stage_ready({})[0] is True  # login CLI suffices


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
