"""Multi-backend model routing (M3 v-next): per-stage model selection.

--verify / --chain / --semantic-dedup can each route to a different model id
(e.g. a cheap model for dedup, a stronger one for verify), falling back to the
single --model default. The routing is resolved at the llm.ask seam; the ambient
backend (env) is shared, so this is per-stage MODEL routing, not per-call
provider switching.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from redteam.pipeline import llm
from redteam.pipeline.models import Finding, TriageReport
from redteam.pipeline.stages import run_triage

_FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"
_BACKEND_VARS = ("ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_MANTLE")


# ---- resolve_model ----------------------------------------------------------


def test_resolve_model_prefers_stage_override():
    assert llm.resolve_model({"verify": "v"}, "verify", "d") == "v"
    assert llm.resolve_model({"verify": "v"}, "chain", "d") == "d"  # no override -> default
    assert llm.resolve_model(None, "verify", "d") == "d"
    assert llm.resolve_model({}, "verify", None) is None
    assert llm.resolve_model({"verify": ""}, "verify", "d") == "d"  # empty override falls back


# ---- run_triage routing -----------------------------------------------------


def _spy():
    seen: dict[str, str | None] = {}

    async def ask(system, user, *, model=None):
        if "deduplicating" in system:
            seen["dedup"] = model
            return "[]"
        if "exploit chains" in system:
            seen["chain"] = model
            return "[]"
        if "adversarial security reviewer" in system:
            seen["verify"] = model
            return "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable"
        return ""

    ask.seen = seen
    return ask


def _two_findings():
    return [
        Finding(title="SQL injection", severity="critical", location="a.py:1", evidence={"s": "x"}),
        Finding(title="SSRF", severity="high", location="b.py:2", evidence={"s": "y"}),
    ]


def test_run_triage_routes_each_stage_to_its_model():
    ask = _spy()
    run_triage(
        _two_findings(),
        verify=True,
        chain=True,
        semantic_dedup=True,
        model="default-m",
        models={"verify": "vm", "chain": "cm", "dedup": "dm"},
        ask=ask,
    )
    assert ask.seen == {"verify": "vm", "chain": "cm", "dedup": "dm"}


def test_run_triage_falls_back_to_default_model():
    ask = _spy()
    run_triage(
        _two_findings(),
        verify=True,
        chain=True,
        model="D",
        models={"chain": "cm"},  # only chain overridden
        ask=ask,
    )
    assert ask.seen["verify"] == "D"  # fell back to --model
    assert ask.seen["chain"] == "cm"


# ---- CLI wiring -------------------------------------------------------------


def test_cli_builds_per_stage_models(tmp_path, monkeypatch):
    from redteam.cli import main

    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: "/usr/local/bin/claude")

    captured: dict = {}

    def fake_run_triage(findings, **kwargs):
        captured.update(kwargs)
        return TriageReport(engagement_id=kwargs.get("engagement_id", "E"), metrics={"kept": 0, "dropped": 0, "input": 0})

    monkeypatch.setattr("redteam.pipeline.stages.run_triage", fake_run_triage)

    out = tmp_path / "out"
    result = CliRunner().invoke(
        main,
        [
            "triage", str(_FIXTURE), "--out", str(out),
            "--verify", "--chain", "--semantic-dedup",
            "--model", "D", "--verify-model", "VM", "--chain-model", "CM", "--dedup-model", "DM",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["model"] == "D"
    assert captured["models"] == {"verify": "VM", "chain": "CM", "dedup": "DM"}


def test_cli_no_per_stage_models_passes_empty_dict(tmp_path, monkeypatch):
    from redteam.cli import main

    monkeypatch.setattr("redteam.preflight.find_cli", lambda: "/usr/local/bin/claude")
    captured: dict = {}
    monkeypatch.setattr(
        "redteam.pipeline.stages.run_triage",
        lambda findings, **kw: captured.update(kw) or TriageReport(engagement_id="E", metrics={"kept": 0, "dropped": 0, "input": 0}),
    )
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(_FIXTURE), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert captured["models"] == {}  # no overrides
