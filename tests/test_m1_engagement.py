"""M1 acceptance (credential-free): a contained engagement's recorded actions
seal into a verifiable ledger and a SARIF artifact.

The autonomous part of a real run (the model *choosing* to call tools) needs a
live backend, but everything downstream of a tool decision is exercised here
end-to-end through the real components: a signed session start, an allowed
in-scope call and a denied out-of-scope call (both via the runtime hook), a
finding written through the report pack, a KMS-less HMAC seal, and a clean
`redteam-verify`. This is the spine an operator relies on; pinning it means the
only thing the live smoke adds is model autonomy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("claude_agent_sdk")  # drives the real report @tool

import redteam.tools.report as report
from redteam.engagement import Engagement
from redteam.ledger.verify import main as verify_main
from redteam.orchestrator import Orchestrator


def _pre_decisions(ledger_path: Path) -> list[str]:
    out = []
    for line in ledger_path.read_text().splitlines():
        payload = json.loads(line).get("payload", {})
        if payload.get("kind") == "tool.pre":
            out.append(payload["decision"])
    return out


async def test_contained_engagement_seals_records_and_verifies(
    tmp_path, minimal_engagement_dict, monkeypatch
):
    key = b"k" * 32
    keyfile = tmp_path / "hmac.key"
    keyfile.write_bytes(key)
    dest = tmp_path / "findings.sarif"
    eng = Engagement.model_validate(
        {**minimal_engagement_dict, "reporting": {"format": "sarif", "destination": str(dest)}}
    )
    orch = Orchestrator(
        engagement=eng,
        engagement_path=tmp_path / "e.yaml",
        audit_dir=tmp_path / "audit",
        hmac_key=key,
    )
    orch.start_session(signature={"principal": eng.operator, "ok": True, "detail": "test"})

    # An allowed in-scope read and a denied out-of-scope call, through the gate.
    await orch._pre_tool_use(
        {"tool_name": "mcp__whitebox__whitebox__repo_read", "tool_input": {"path": "app.py"},
         "session_id": "s", "tool_use_id": "t1"}, "t1", None,
    )
    deny = await orch._pre_tool_use(
        {"tool_name": "mcp__web__web__http_request", "tool_input": {"url": "https://evil.example.com/"},
         "session_id": "s", "tool_use_id": "t2"}, "t2", None,
    )
    assert deny["hookSpecificOutput"]["permissionDecision"] == "deny"

    # A finding through the real report pack tool -> SARIF + ledger.
    captured: dict = {}

    def fake(name, version, tools):
        captured["tools"] = tools
        return {}

    monkeypatch.setattr(report, "create_sdk_mcp_server", fake)
    report.build_pack(orch.tool_ctx)
    write = {t.name: t for t in captured["tools"]}["report__write_finding"]
    await write.handler(
        title="Unauthenticated PII endpoint", severity="high",
        description="GET /users returns PII without auth", location="app.py:42",
    )

    result = orch.seal(status="complete")

    # SARIF artifact written atomically with the finding.
    doc = json.loads(dest.read_text())
    assert doc["runs"][0]["results"][0]["ruleId"] == "Unauthenticated PII endpoint"
    assert doc["runs"][0]["results"][0]["level"] == "error"  # high -> error

    # The sealed, hash-chained ledger verifies under the HMAC key.
    ledger_path = orch.audit_dir / f"{eng.id}.jsonl"
    assert result.seal_path is not None and result.seal_path.exists()
    rc = verify_main([str(ledger_path), str(result.seal_path), "--hmac-key-file", str(keyfile)])
    assert rc == 0, f"redteam-verify exited {rc}"

    # Cage proof in the audit trail: both an allow and a deny were recorded.
    decisions = _pre_decisions(ledger_path)
    assert "allow" in decisions and "deny" in decisions

    # And a wrong key must NOT pass (the seal is a real trust anchor).
    badkey = tmp_path / "bad.key"
    badkey.write_bytes(b"x" * 32)
    assert verify_main([str(ledger_path), str(result.seal_path), "--hmac-key-file", str(badkey)]) != 0
