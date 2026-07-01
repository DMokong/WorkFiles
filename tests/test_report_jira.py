"""report__jira_upsert tool + reporting.jira_project schema (build-next #5).

The Jira upsert tool is only exposed when the engagement enables the Atlassian
MCP AND sets reporting.jira_project. It returns a deterministic, idempotent
upsert plan the agent then executes via the atlassian__* MCP tools.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redteam import jira
from redteam.engagement import Engagement
from redteam.hooks.audit_writer import AuditWriter
from redteam.hooks.scope_guard import ScopeGuard, _TARGETLESS_TOOLS
from redteam.ledger.chain import LedgerWriter
from redteam.tools import report
from redteam.tools._context import ToolContext
from redteam.assets import build_index


def _atlassian_dict(base: dict, *, project: str | None = "SEC", with_mcp: bool = True) -> dict:
    d = {**base}
    d["scope"] = {**base["scope"], "egress_allowlist": [*base["scope"]["egress_allowlist"], "mcp.atlassian.com"]}
    if with_mcp:
        d["external_mcp"] = [
            {
                "name": "atlassian",
                "transport": "http",
                "url": "https://mcp.atlassian.com/v1/sse",
                "allowed_tools": ["searchJiraIssuesUsingJql", "createJiraIssue", "editJiraIssue"],
            }
        ]
    reporting = {"format": "sarif", "destination": "/tmp/redteam-x.sarif"}
    if project is not None:
        reporting["jira_project"] = project
    d["reporting"] = reporting
    return d


def _ctx(eng: Engagement, tmp_path) -> ToolContext:
    return ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter(tmp_path / "l.jsonl")),
        assets=build_index(eng.assets, host_root=tmp_path, require_exists=False),
        audit_dir=tmp_path / "audit",
    )


def _tools(ctx, monkeypatch) -> dict:
    cap: dict = {}
    monkeypatch.setattr(report, "create_sdk_mcp_server", lambda name, version, tools: cap.update(t=tools))
    report.build_pack(ctx)
    return {t.name: t for t in cap["t"]}


# ---- schema -----------------------------------------------------------------


def test_reporting_jira_project_optional_and_validated(minimal_engagement_dict) -> None:
    Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project="SEC"))
    Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project=None))  # omitted OK
    for bad in ['SEC"; DROP', "has space", "-bad", ""]:
        with pytest.raises(ValidationError):
            Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project=bad))


# ---- tool presence gating ---------------------------------------------------


def test_jira_tool_absent_without_atlassian(minimal_engagement_dict, tmp_path, monkeypatch) -> None:
    eng = Engagement.model_validate({**minimal_engagement_dict, "tools": ["report"]})
    names = set(_tools(_ctx(eng, tmp_path), monkeypatch))
    assert "report__write_finding" in names
    assert "report__jira_upsert" not in names


def test_jira_tool_absent_without_project(minimal_engagement_dict, tmp_path, monkeypatch) -> None:
    eng = Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project=None))
    names = set(_tools(_ctx(eng, tmp_path), monkeypatch))
    assert "report__jira_upsert" not in names


def test_jira_tool_present_with_atlassian_and_project(minimal_engagement_dict, tmp_path, monkeypatch) -> None:
    eng = Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project="SEC"))
    names = set(_tools(_ctx(eng, tmp_path), monkeypatch))
    assert "report__jira_upsert" in names


# ---- tool behaviour ---------------------------------------------------------


async def test_jira_upsert_returns_create_plan(minimal_engagement_dict, tmp_path, monkeypatch) -> None:
    eng = Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project="SEC"))
    tool = _tools(_ctx(eng, tmp_path), monkeypatch)["report__jira_upsert"]
    res = await tool.handler(title="SQL injection", severity="critical", description="d", location="app/db.py:10")
    assert res["action"] == "create" and res["issue_key"] is None
    assert res["external_key"] == jira.external_key(eng.id, "SQL injection", "app/db.py:10")
    assert res["fields"]["priority"] == {"name": "Highest"}
    assert 'labels = "' in res["jql"]


async def test_jira_upsert_returns_update_plan_on_match(minimal_engagement_dict, tmp_path, monkeypatch) -> None:
    eng = Engagement.model_validate(_atlassian_dict(minimal_engagement_dict, project="SEC"))
    tool = _tools(_ctx(eng, tmp_path), monkeypatch)["report__jira_upsert"]
    key = jira.external_key(eng.id, "SQLi", "a.py:1")
    existing = [{"key": "SEC-7", "fields": {"labels": [key]}}]
    res = await tool.handler(title="SQLi", severity="high", description="d", location="a.py:1", existing_issues=existing)
    assert res["action"] == "update" and res["issue_key"] == "SEC-7"


def test_jira_upsert_is_targetless() -> None:
    assert "report__jira_upsert" in _TARGETLESS_TOOLS
