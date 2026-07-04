"""RT-22: the app configures a real TracerProvider and emits its own spans.

Before this, `telemetry.py` used the global no-op tracer, so tool_span /
event_* recorded nothing. These tests use an in-memory span exporter (no
network, no global state) to prove the tool.invoked / tool.denied /
finding.recorded spans are actually produced with their attributes.
"""

from __future__ import annotations

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from redteam.hooks.telemetry import Telemetry, build_tracer_provider


def _mem():
    exp = InMemorySpanExporter()
    prov = TracerProvider(resource=Resource.create({"service.name": "test"}))
    prov.add_span_processor(SimpleSpanProcessor(exp))
    return prov, exp


def test_tool_invoked_and_denied_emit_spans_with_attrs():
    prov, exp = _mem()
    t = Telemetry("svc", tracer_provider=prov)
    t.event_tool_invoked("mcp__web__http_request", "https://staging.example.com")
    t.event_tool_denied("mcp__web__http_request", "out of scope")

    spans = {s.name: s for s in exp.get_finished_spans()}
    assert "tool.invoked" in spans and "tool.denied" in spans
    assert spans["tool.invoked"].attributes.get("redteam.tool.name") == "mcp__web__http_request"
    assert spans["tool.invoked"].attributes.get("redteam.tool.target") == "https://staging.example.com"
    assert spans["tool.denied"].attributes.get("redteam.tool.deny_reason") == "out of scope"


def test_finding_recorded_emits_span():
    prov, exp = _mem()
    Telemetry("svc", tracer_provider=prov).event_finding("high", "SQL injection")
    spans = {s.name: s for s in exp.get_finished_spans()}
    assert "finding.recorded" in spans
    assert spans["finding.recorded"].attributes.get("redteam.finding.severity") == "high"
    assert spans["finding.recorded"].attributes.get("redteam.finding.title") == "SQL injection"


def test_tool_span_wraps_and_parents_child_events():
    prov, exp = _mem()
    t = Telemetry("svc", tracer_provider=prov)
    with t.tool_span("mcp__web__http_request", {"target": "https://x"}) as span:
        assert span is not None
        t.event_tool_invoked("mcp__web__http_request", "https://x")

    by_name = {s.name: s for s in exp.get_finished_spans()}
    assert "tool:mcp__web__http_request" in by_name and "tool.invoked" in by_name
    # The invoked span is a child of the wrapping tool span.
    assert by_name["tool.invoked"].parent is not None
    assert by_name["tool.invoked"].parent.span_id == by_name["tool:mcp__web__http_request"].context.span_id


def test_degrades_with_no_tracer():
    t = Telemetry.__new__(Telemetry)
    t.service_name, t._tracer = "svc", None  # simulate OTel absent / no provider
    t.event_tool_invoked("x", "y")
    t.event_tool_denied("x", "r")
    t.event_finding("high", "t")
    with t.tool_span("x", {}) as s:
        assert s is None  # no crash, no span


def test_build_tracer_provider_none_without_endpoint_or_exporter():
    assert build_tracer_provider("svc") is None  # nothing to export to -> no-op


def test_build_tracer_provider_with_injected_exporter_records():
    exp = InMemorySpanExporter()
    prov = build_tracer_provider("svc", span_exporter=exp)
    assert prov is not None
    prov.get_tracer("svc").start_span("x").end()
    assert any(s.name == "x" for s in exp.get_finished_spans())


# ---- wiring: orchestrator hook + report pack --------------------------------


async def test_orchestrator_pre_tool_use_emits_tool_spans(minimal_engagement_dict, tmp_path):
    from redteam.engagement import Engagement
    from redteam.orchestrator import Orchestrator

    prov, exp = _mem()
    eng = Engagement.model_validate(minimal_engagement_dict)
    orch = Orchestrator(engagement=eng, engagement_path=tmp_path / "e.yaml", audit_dir=tmp_path / "audit")
    orch.telemetry = Telemetry("t", tracer_provider=prov)

    # Allowed (targetless whitebox read) then denied (out-of-scope URL).
    await orch._pre_tool_use(
        {"tool_name": "mcp__whitebox__whitebox__repo_read", "tool_input": {"path": "a.py"},
         "session_id": "s", "tool_use_id": "t1"}, "t1", None)
    await orch._pre_tool_use(
        {"tool_name": "mcp__web__web__http_request", "tool_input": {"url": "https://evil.example.com/"},
         "session_id": "s", "tool_use_id": "t2"}, "t2", None)

    names = [s.name for s in exp.get_finished_spans()]
    assert "tool.invoked" in names and "tool.denied" in names
    assert any(n.startswith("tool:") for n in names)  # the wrapping tool_span


async def test_report_write_finding_emits_finding_span(minimal_engagement_dict, tmp_path, monkeypatch):
    from redteam.assets import build_index
    from redteam.engagement import Engagement
    from redteam.hooks.audit_writer import AuditWriter
    from redteam.hooks.scope_guard import ScopeGuard
    from redteam.ledger.chain import LedgerWriter
    from redteam.tools import report
    from redteam.tools._context import ToolContext

    prov, exp = _mem()
    dest = tmp_path / "f.sarif"
    eng = Engagement.model_validate(
        {**minimal_engagement_dict, "tools": ["report"],
         "reporting": {"format": "sarif", "destination": str(dest)}})
    ctx = ToolContext(
        engagement=eng, scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter(tmp_path / "l.jsonl")),
        assets=build_index(eng.assets, host_root=tmp_path, require_exists=False),
        audit_dir=tmp_path / "audit", telemetry=Telemetry("t", tracer_provider=prov))

    cap: dict = {}
    monkeypatch.setattr(report, "create_sdk_mcp_server", lambda name, version, tools: cap.update(t=tools))
    report.build_pack(ctx)
    write = {t.name: t for t in cap["t"]}["report__write_finding"]
    await write.handler(title="SQL injection", severity="high", description="d")

    assert any(s.name == "finding.recorded" for s in exp.get_finished_spans())
