"""M1 / RT-21: the report pack's SARIF writer is atomic and concurrency-safe.

The report pack records findings to SARIF on the audit volume. The first cut did
a non-atomic read-modify-write per finding (`path.write_text` over the whole
doc), so a crash mid-write corrupts the file and concurrent subagent findings
can clobber each other. M1 makes the write atomic (temp + os.replace) and
serializes it behind an asyncio.Lock.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("claude_agent_sdk")  # tests drive the real @tool's .name/.handler

import redteam.tools.report as report
from redteam.assets import build_index
from redteam.engagement import Engagement
from redteam.hooks.audit_writer import AuditWriter
from redteam.hooks.scope_guard import ScopeGuard
from redteam.ledger.chain import LedgerWriter
from redteam.tools._context import ToolContext


def _ctx(tmp_path: Path, dest: Path, minimal_engagement_dict: dict) -> ToolContext:
    minimal_engagement_dict = {
        **minimal_engagement_dict,
        "tools": ["report"],
        "reporting": {"format": "sarif", "destination": str(dest)},
    }
    eng = Engagement.model_validate(minimal_engagement_dict)
    assets = build_index(eng.assets, host_root=tmp_path, require_exists=False)
    return ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter(tmp_path / "ledger.jsonl")),
        assets=assets,
        audit_dir=tmp_path / "audit",
    )


def _write_finding_tool(ctx: ToolContext, monkeypatch):
    captured = {}

    def fake(name, version, tools):
        captured["tools"] = tools
        return {"name": name, "tools": tools}

    monkeypatch.setattr(report, "create_sdk_mcp_server", fake)
    report.build_pack(ctx)
    return {t.name: t for t in captured["tools"]}["report__write_finding"]


# ---------------------------------------------------------------- atomic write
class TestAtomicWrite:
    def test_atomic_write_json_durable_no_tmp_left(self, tmp_path: Path):
        dest = tmp_path / "out.sarif"
        report._atomic_write_json(dest, {"a": 1, "runs": []})
        assert json.loads(dest.read_text()) == {"a": 1, "runs": []}
        # no temp sibling left behind
        assert list(tmp_path.glob("*.tmp")) == []

    def test_failed_serialization_preserves_existing(self, tmp_path: Path):
        dest = tmp_path / "out.sarif"
        report._atomic_write_json(dest, {"results": ["first"]})
        # a set is not JSON-serializable -> the write must fail WITHOUT clobbering
        # the existing good file or leaving a partial temp.
        import pytest

        with pytest.raises(TypeError):
            report._atomic_write_json(dest, {"bad": {1, 2, 3}})
        assert json.loads(dest.read_text()) == {"results": ["first"]}
        assert list(tmp_path.glob("*.tmp")) == []


# ---------------------------------------------------------------- via the tool
class TestWriteFindingTool:
    async def test_two_findings_both_appended_valid_sarif(self, tmp_path, minimal_engagement_dict, monkeypatch):
        dest = tmp_path / "findings.sarif"
        tool = _write_finding_tool(_ctx(tmp_path, dest, minimal_engagement_dict), monkeypatch)
        await tool.handler(title="A", severity="low", description="d1")
        await tool.handler(title="B", severity="critical", description="d2", location="src/x.py")
        doc = json.loads(dest.read_text())
        results = doc["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == ["A", "B"]
        assert [r["level"] for r in results] == ["note", "error"]  # low->note, critical->error
        assert results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/x.py"

    async def test_corrupt_base_sarif_quarantined_finding_still_recorded(
        self, tmp_path, minimal_engagement_dict, monkeypatch
    ):
        # If the on-disk SARIF was corrupted out-of-band (truncation, manual
        # edit), the finding must still reach a fresh SARIF (the ledger stays
        # authoritative either way) rather than the write throwing.
        dest = tmp_path / "findings.sarif"
        dest.write_text("{ this is not valid json", encoding="utf-8")
        tool = _write_finding_tool(_ctx(tmp_path, dest, minimal_engagement_dict), monkeypatch)
        await tool.handler(title="A", severity="low", description="d")
        doc = json.loads(dest.read_text())  # valid again
        assert [r["ruleId"] for r in doc["runs"][0]["results"]] == ["A"]
        assert (tmp_path / "findings.sarif.corrupt").exists()  # old doc quarantined

    async def test_concurrent_findings_lose_nothing(self, tmp_path, minimal_engagement_dict, monkeypatch):
        dest = tmp_path / "findings.sarif"
        tool = _write_finding_tool(_ctx(tmp_path, dest, minimal_engagement_dict), monkeypatch)
        # Proves concurrent invocations all land (no lost finding). Today the
        # single event loop already serializes the no-await critical section; the
        # build_pack lock is the correct insurance that keeps this true the moment
        # an await (e.g. an async ledger write) enters that section.
        await asyncio.gather(
            *(tool.handler(title=f"F{i}", severity="medium", description=str(i)) for i in range(12))
        )
        doc = json.loads(dest.read_text())
        titles = {r["ruleId"] for r in doc["runs"][0]["results"]}
        assert titles == {f"F{i}" for i in range(12)}, "a concurrent write was lost"
