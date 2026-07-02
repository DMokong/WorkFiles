"""Semantic/LLM dedup (M3 v-next): model-assisted dedup atop deterministic dedup.

Conservative by construction — the danger here is a FALSE NEGATIVE (merging two
distinct findings makes a real vuln vanish), so:
  - only findings the model groups as the SAME issue AND sharing the canonical's
    file are merged (a cross-file "duplicate" is refused);
  - group indices are deterministically validated (in range, disjoint);
  - every merge is RECORDED in report.dropped (auditable / recoverable), never
    silently deleted;
  - a bad / unparseable / errored model reply degrades (keep everything).
Every test injects a fake ``ask`` — no live model.
"""

from __future__ import annotations

import asyncio

from redteam.pipeline.models import Finding
from redteam.pipeline.stages import run_triage, semantic_dedup_findings


def _f(title, loc, sev="high"):
    return Finding(title=title, severity=sev, location=loc, evidence={"snippet": "x"})


def _ask(payload):
    async def ask(system, user, *, model=None):
        return payload

    return ask


def _run(coro):
    return asyncio.run(coro)


def test_merges_same_file_reworded_duplicate():
    a = _f("SQL injection in get_user", "app/users.py:21")
    b = _f("Unsanitized user_id reaches DB query", "app/users.py:21")
    kept, dropped, degraded = _run(
        semantic_dedup_findings([a, b], ask=_ask('[{"canonical":0,"duplicates":[1],"reason":"same SQLi, reworded"}]'))
    )
    assert [f.title for f in kept] == ["SQL injection in get_user"]
    assert len(dropped) == 1 and dropped[0].reason == "DUPLICATE"
    assert "semantic" in dropped[0].detail.lower()
    assert any(d.file == "app/users.py" for d in kept[0].duplicates)
    assert not degraded


def test_refuses_cross_file_merge():
    a = _f("SQLi", "app/users.py:21")
    b = _f("SQLi", "app/orders.py:9")  # different file -> NOT the same finding
    kept, dropped, degraded = _run(
        semantic_dedup_findings([a, b], ask=_ask('[{"canonical":0,"duplicates":[1],"reason":"both sqli"}]'))
    )
    assert len(kept) == 2 and dropped == [] and not degraded


def test_rejects_out_of_range_and_overlapping_indices():
    a, b, c = _f("a", "f.py:1"), _f("b", "f.py:1"), _f("c", "f.py:1")
    # group1 merges 1 into 0; group2 tries to reuse 1 (overlap) and 99 (oob).
    payload = (
        '[{"canonical":0,"duplicates":[1],"reason":"x"},'
        '{"canonical":2,"duplicates":[1,99],"reason":"y"}]'
    )
    kept, dropped, degraded = _run(semantic_dedup_findings([a, b, c], ask=_ask(payload)))
    assert {f.title for f in kept} == {"a", "c"} and len(dropped) == 1


def test_canonical_cannot_duplicate_itself():
    a, b = _f("a", "f.py:1"), _f("b", "f.py:1")
    kept, _, _ = _run(semantic_dedup_findings([a, b], ask=_ask('[{"canonical":0,"duplicates":[0],"reason":"self"}]')))
    assert len(kept) == 2  # self-reference produces no valid duplicate -> no merge


def test_unparseable_reply_degrades_keep_all():
    a, b = _f("a", "f.py:1"), _f("b", "f.py:1")
    kept, dropped, degraded = _run(semantic_dedup_findings([a, b], ask=_ask("no json here at all")))
    assert len(kept) == 2 and dropped == [] and degraded


def test_empty_array_is_not_degraded():
    a, b = _f("a", "f.py:1"), _f("b", "f.py:1")
    kept, dropped, degraded = _run(semantic_dedup_findings([a, b], ask=_ask("[]")))
    assert len(kept) == 2 and dropped == [] and not degraded


def test_ask_failure_degrades():
    async def boom(system, user, *, model=None):
        raise RuntimeError("no model")

    a, b = _f("a", "f.py:1"), _f("b", "f.py:1")
    kept, dropped, degraded = _run(semantic_dedup_findings([a, b], ask=boom))
    assert len(kept) == 2 and degraded


def test_fewer_than_two_is_noop():
    a = _f("a", "f.py:1")
    kept, dropped, degraded = _run(semantic_dedup_findings([a], ask=_ask("[]")))
    assert kept == [a] and dropped == [] and not degraded


def test_total_on_oversized_string_index():
    # A quoted >4300-digit index must NOT crash (Py3.14 int(str) cap); it is
    # simply not a valid index -> no merge, keep all.
    a, b = _f("a", "f.py:1"), _f("b", "f.py:1")
    payload = '[{"canonical":"' + "9" * 4400 + '","duplicates":[1]}]'
    kept, dropped, degraded = _run(semantic_dedup_findings([a, b], ask=_ask(payload)))
    assert len(kept) == 2 and dropped == []


def test_accepts_single_group_object():
    # The model may return one group as a bare object (not wrapped in an array).
    a, b = _f("SQLi", "app/u.py:1"), _f("SQLi reworded", "app/u.py:1")
    kept, dropped, degraded = _run(
        semantic_dedup_findings([a, b], ask=_ask('{"canonical":0,"duplicates":[1],"reason":"same"}'))
    )
    assert len(kept) == 1 and len(dropped) == 1 and not degraded


# ---- run_triage integration -------------------------------------------------


def test_run_triage_semantic_dedup_collapses_reworded_pair():
    # Same file + line, but different vuln_class labels so DETERMINISTIC dedup
    # (keyed on (file, vuln_class)) keeps both; semantic dedup then merges them.
    a = _f("SQL injection in get_user via f-string", "app/users.py:21", sev="critical")
    b = _f("Improper input validation of user_id parameter", "app/users.py:21", sev="high")

    async def ask(system, user, *, model=None):
        return '[{"canonical":0,"duplicates":[1],"reason":"same root cause"}]'

    without = run_triage([a.model_copy(deep=True), b.model_copy(deep=True)], engagement_id="E")
    with_sem = run_triage([a, b], engagement_id="E", semantic_dedup=True, ask=ask)
    assert len(without.findings) == 2  # deterministic dedup keeps both
    assert len(with_sem.findings) == 1  # semantic dedup collapses them
    assert with_sem.metrics["dropped_by_reason"].get("DUPLICATE", 0) >= 1


# ---- CLI --semantic-dedup gating --------------------------------------------

from pathlib import Path  # noqa: E402

from click.testing import CliRunner  # noqa: E402

from redteam.cli import main  # noqa: E402

_FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"
_BACKEND_VARS = ("ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_MANTLE")


def test_cli_semantic_dedup_refused_without_model(tmp_path, monkeypatch):
    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: None)
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(_FIXTURE), "--out", str(out), "--semantic-dedup"])
    assert result.exit_code != 0 and "Traceback" not in result.output
    assert not out.exists()  # no artifacts when the gate refuses


def test_cli_semantic_dedup_runs_with_logged_in_cli(tmp_path, monkeypatch):
    for var in _BACKEND_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("redteam.preflight.find_cli", lambda: "/usr/local/bin/claude")

    async def fake_ask(system, user, *, model=None):
        return "[]"  # no groups -> deterministic-equivalent, but the stage ran

    monkeypatch.setattr("redteam.pipeline.llm.ask", fake_ask)
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["triage", str(_FIXTURE), "--out", str(out), "--semantic-dedup"])
    assert result.exit_code == 0, result.output
    assert (out / f"{_FIXTURE.stem}.triage.json").exists()
