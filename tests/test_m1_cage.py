"""M1: the cage is validated at the contract level — the PreToolUse hook allows
in-scope calls, denies out-of-scope ones, denies outside the window, and fails
CLOSED on an internal error — and *records every decision in the ledger*.

A real engagement (the agent autonomously calling tools) needs a live model
backend; this pins the exact runtime-hook behaviour that the live run depends
on, without spending a token. It is the unit-level proof behind M1's "an
out-of-scope call must be denied and recorded as a denial" acceptance.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redteam.engagement import Engagement
from redteam.orchestrator import Orchestrator


def _orch(tmp_path: Path, eng_dict: dict, **overrides) -> Orchestrator:
    # The scope guard inspects tool *names*, not the loaded packs, so the
    # engagement's tools list is irrelevant here — keep the fixture default
    # (no assets required) and drive the hook with web/whitebox tool names.
    eng = Engagement.model_validate({**eng_dict, **overrides})
    orch = Orchestrator(engagement=eng, engagement_path=tmp_path / "e.yaml", audit_dir=tmp_path / "audit")
    orch.audit_dir.mkdir(parents=True, exist_ok=True)  # start_session() would do this in a real run
    return orch


def _pre_records(orch: Orchestrator) -> list[dict]:
    path = orch.audit_dir / f"{orch.engagement.id}.jsonl"
    records = []
    for line in path.read_text().splitlines():
        rec = json.loads(line)
        payload = rec.get("payload", rec)
        if payload.get("kind") == "tool.pre":
            records.append(payload)
    return records


async def _drive(orch: Orchestrator, tool_name: str, tool_input: dict, tid: str = "t1") -> dict:
    return await orch._pre_tool_use(
        {"tool_name": tool_name, "tool_input": tool_input, "session_id": "s", "tool_use_id": tid},
        tid,
        None,
    )


def _is_deny(res: dict) -> bool:
    return res.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


class TestCage:
    async def test_in_scope_targetless_allowed_and_recorded(self, tmp_path, minimal_engagement_dict):
        orch = _orch(tmp_path, minimal_engagement_dict)
        res = await _drive(orch, "mcp__whitebox__whitebox__repo_read", {"path": "app.py"})
        assert res == {}, "a targetless whitebox read is in scope -> allow (empty = proceed)"
        rec = _pre_records(orch)[-1]
        assert rec["decision"] == "allow"
        assert "repo_read" in rec["tool"]

    async def test_out_of_scope_denied_and_recorded(self, tmp_path, minimal_engagement_dict):
        orch = _orch(tmp_path, minimal_engagement_dict)
        res = await _drive(orch, "mcp__web__web__http_request", {"url": "https://evil.example.com/"})
        assert _is_deny(res), "an out-of-scope URL must be denied by the gate"
        rec = _pre_records(orch)[-1]
        assert rec["decision"] == "deny"
        # the denied call's input is captured in the ledger for forensics
        assert "evil.example.com" in json.dumps(rec)

    async def test_outside_window_denied_and_recorded(self, tmp_path, minimal_engagement_dict):
        past = datetime.now(timezone.utc) - timedelta(days=2)
        window = {"start": past.isoformat(), "end": (past + timedelta(hours=1)).isoformat()}
        orch = _orch(tmp_path, minimal_engagement_dict, window=window)
        res = await _drive(orch, "mcp__whitebox__whitebox__repo_read", {"path": "app.py"})
        assert _is_deny(res), "a call outside the engagement window must be denied"
        rec = _pre_records(orch)[-1]
        assert rec["decision"] == "deny"
        assert "window" in rec["reason"].lower()

    async def test_internal_error_fails_closed(self, tmp_path, minimal_engagement_dict, monkeypatch):
        orch = _orch(tmp_path, minimal_engagement_dict)

        def boom(*a, **k):
            raise RuntimeError("scope guard exploded")

        monkeypatch.setattr(orch.scope, "check", boom)
        res = await _drive(orch, "mcp__whitebox__whitebox__repo_read", {"path": "app.py"})
        assert _is_deny(res), "an internal error in the gate must DENY, not fail open"
        assert "internal error" in res["hookSpecificOutput"]["permissionDecisionReason"]


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
