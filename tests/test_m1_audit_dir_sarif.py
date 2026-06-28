"""`--audit-dir` co-locates the SARIF report with the audit ledger.

The engagement's `reporting.destination` *filename* is honored, but the report
lands under `--audit-dir` (stripping any directory / path traversal in the
destination), so a host run doesn't need the engagement's container path
`/audit` to be writable, and ledger + report always sit together.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("claude_agent_sdk")

import redteam.tools.report as report
from redteam.assets import build_index
from redteam.cli import _report_destination
from redteam.engagement import Engagement
from redteam.hooks.audit_writer import AuditWriter
from redteam.hooks.scope_guard import ScopeGuard
from redteam.ledger.chain import LedgerWriter
from redteam.tools._context import ToolContext


class TestReportDestination:
    def test_basename_under_audit_dir(self, tmp_path):
        assert _report_destination(tmp_path / "run", "/audit/findings.sarif") == tmp_path / "run" / "findings.sarif"

    def test_strips_directory_and_traversal(self, tmp_path):
        assert _report_destination(tmp_path / "run", "../../etc/evil.sarif") == tmp_path / "run" / "evil.sarif"

    def test_relative_destination(self, tmp_path):
        assert _report_destination(tmp_path / "run", "out/findings.sarif") == tmp_path / "run" / "findings.sarif"

    def test_empty_name_falls_back_to_default(self, tmp_path):
        assert _report_destination(tmp_path / "run", "/") == tmp_path / "run" / "findings.sarif"


async def test_report_pack_writes_under_audit_dir(tmp_path, minimal_engagement_dict, monkeypatch):
    audit = tmp_path / "myrun"
    eng = Engagement.model_validate(
        {**minimal_engagement_dict, "tools": ["report"],
         "reporting": {"format": "sarif", "destination": "/audit/findings.sarif"}}
    )
    # the rewrite the CLI applies
    eng.reporting.destination = _report_destination(audit, eng.reporting.destination)
    ctx = ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter(tmp_path / "ledger.jsonl")),
        assets=build_index(eng.assets, host_root=tmp_path, require_exists=False),
        audit_dir=audit,
    )
    cap: dict = {}
    monkeypatch.setattr(report, "create_sdk_mcp_server", lambda name, version, tools: cap.update(t=tools))
    report.build_pack(ctx)
    write = {x.name: x for x in cap["t"]}["report__write_finding"]
    await write.handler({"title": "T", "severity": "low", "description": "d"})

    assert (audit / "findings.sarif").exists(), "SARIF must land under --audit-dir"
    assert json.loads((audit / "findings.sarif").read_text())["runs"][0]["results"][0]["ruleId"] == "T"
