"""M1 / SDK contract: the in-process MCP tool handlers are invoked by the SDK
with a SINGLE arguments dict (`await handler(arguments)`) and must return
`{"content": [...]}`.

The first live engagement proved every tool crashed at the SDK boundary
("repo_grep() missing 1 required positional argument: 'role'", etc.) because the
handlers were defined with unpacked params and the unit tests only ever called
`.handler(**kwargs)` — never the way the SDK calls them. These tests pin the
real convention so the whole tool surface can't silently regress to unusable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("claude_agent_sdk")

import redteam.tools.report as report
import redteam.tools.whitebox as whitebox
from redteam.assets import build_index
from redteam.engagement import Assets, Engagement, SourceRepo
from redteam.hooks.audit_writer import AuditWriter
from redteam.hooks.scope_guard import ScopeGuard
from redteam.ledger.chain import LedgerWriter
from redteam.tools._context import ToolContext


def _tools(module, ctx, monkeypatch) -> dict:
    cap: dict = {}
    monkeypatch.setattr(
        module, "create_sdk_mcp_server", lambda name, version, tools: cap.update(t=tools)
    )
    module.build_pack(ctx)
    return {t.name: t for t in cap["t"]}


def _ctx(eng: Engagement, assets, tmp_path: Path) -> ToolContext:
    return ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter(tmp_path / "ledger.jsonl")),
        assets=assets,
        audit_dir=tmp_path / "audit",
    )


async def test_report_handler_single_dict_returns_mcp_content(
    tmp_path, minimal_engagement_dict, monkeypatch
):
    dest = tmp_path / "f.sarif"
    eng = Engagement.model_validate(
        {**minimal_engagement_dict, "tools": ["report"], "reporting": {"format": "sarif", "destination": str(dest)}}
    )
    ctx = _ctx(eng, build_index(eng.assets, host_root=tmp_path, require_exists=False), tmp_path)
    write = _tools(report, ctx, monkeypatch)["report__write_finding"]

    # The SDK invokes the handler with ONE positional dict.
    res = await write.handler({"title": "T", "severity": "low", "description": "d"})
    assert isinstance(res, dict) and "content" in res, "handler must return MCP {'content': [...]}"
    assert res["content"][0]["type"] == "text"
    assert json.loads(dest.read_text())["runs"][0]["results"][0]["ruleId"] == "T"


async def test_whitebox_grep_handler_single_dict(tmp_path, minimal_engagement_dict, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("PASSWORD = 'hunter2'\n")
    assets = build_index(
        Assets(source_repos=[SourceRepo(path=Path("repo"), language="python", role="backend")]),
        host_root=tmp_path,
    )
    eng = Engagement.model_validate(minimal_engagement_dict)
    grep = _tools(whitebox, _ctx(eng, assets, tmp_path), monkeypatch)["whitebox__repo_grep"]

    res = await grep.handler({"pattern": "PASSWORD", "role": "backend"})
    assert "content" in res
    data = json.loads(res["content"][0]["text"])
    assert any(m["path"] == "a.py" for m in data["matches"]), "grep must find the match via the SDK path"


async def test_kwargs_call_still_works_for_direct_tests(tmp_path, minimal_engagement_dict, monkeypatch):
    # Existing tests call .handler(**kwargs) and assert on the raw dict; that path
    # must keep working (raw dict out) alongside the SDK single-dict path.
    eng = Engagement.model_validate(minimal_engagement_dict)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    assets = build_index(
        Assets(source_repos=[SourceRepo(path=Path("repo"), language="python", role="backend")]),
        host_root=tmp_path,
    )
    grep = _tools(whitebox, _ctx(eng, assets, tmp_path), monkeypatch)["whitebox__repo_grep"]
    res = await grep.handler(pattern="x", role="backend")
    assert "matches" in res and "content" not in res  # raw dict for direct/test callers
