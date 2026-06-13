"""Regression tests for review findings RT-09, RT-10, RT-12, RT-13, RT-15.

(RT-14 is a container-runtime fix - Dockerfile/compose/entrypoint - and is not
unit-testable here; see docs/REVIEW.md.)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redteam.assets import build_index
from redteam.engagement import Assets, Engagement, SourceRepo
from redteam.hooks.audit_writer import AuditWriter
from redteam.hooks.scope_guard import ScopeGuard
from redteam.ledger.chain import LedgerWriter
from redteam.orchestrator import Orchestrator
from redteam.tools._context import ToolContext


def _ctx(engagement: Engagement, assets, tmp_path: Path) -> ToolContext:
    return ToolContext(
        engagement=engagement,
        scope=ScopeGuard(engagement),
        audit=AuditWriter(LedgerWriter(tmp_path / "ledger.jsonl")),
        assets=assets,
        audit_dir=tmp_path / "audit",
    )


def _pack_tools(module, ctx, monkeypatch) -> dict:
    """Build a pack and return its tools by name.

    create_sdk_mcp_server registers the tools onto an mcp Server instance and
    doesn't expose them, so we intercept the call to capture the SdkMcpTool
    list (each carries .name and the raw async .handler).
    """
    captured = {}

    def fake(name, version, tools):
        captured["tools"] = tools
        return {"name": name, "version": version, "tools": tools}

    monkeypatch.setattr(module, "create_sdk_mcp_server", fake)
    module.build_pack(ctx)
    return {t.name: t for t in captured["tools"]}


# ---------------------------------------------------------------- RT-09
class TestRT09SymlinkContainment:
    async def test_repo_grep_does_not_follow_symlink_out_of_repo(self, tmp_path, minimal_engagement_dict, monkeypatch):
        import redteam.tools.whitebox as wb

        # secret lives OUTSIDE the cloned repo; a symlink inside the repo points at it.
        secret = tmp_path / "secret.txt"
        secret.write_text("TOPSECRET_TOKEN_ghp_xxxx")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("# the needle is here\nNEEDLE = 1\n")
        (repo / "leak").symlink_to(secret)  # planted symlink escaping the mount

        assets = build_index(
            Assets(source_repos=[SourceRepo(path=Path("repo"), language="python", role="backend")]),
            host_root=tmp_path,
        )
        eng = Engagement.model_validate(minimal_engagement_dict)
        grep = _pack_tools(wb, _ctx(eng, assets, tmp_path), monkeypatch)["whitebox__repo_grep"]

        res = await grep.handler(pattern=".", role="backend")
        files = {m["path"] for m in res["matches"]}
        blob = json.dumps(res)
        assert "app.py" in files, "the real repo file must be searchable"
        assert "TOPSECRET" not in blob, "must not read through a symlink escaping the repo"
        assert "leak" not in files


# ---------------------------------------------------------------- RT-10
class TestRT10WriteMethods:
    def _web(self, tmp_path, dict_, monkeypatch):
        import redteam.tools.web as web

        class _Resp:
            status = 200
            headers: dict = {}

            def read(self, n):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _Opener:
            def open(self, req, data=None, timeout=None):
                return _Resp()

        monkeypatch.setattr(web, "_build_no_redirect_opener", lambda: _Opener())
        eng = Engagement.model_validate(dict_)
        return _pack_tools(web, _ctx(eng, None, tmp_path), monkeypatch)["web__http_request"]

    def test_schema_defaults_read_only(self, minimal_engagement_dict):
        eng = Engagement.model_validate(minimal_engagement_dict)
        assert eng.scope.allow_write_methods is False

    async def test_write_method_refused_by_default(self, tmp_path, minimal_engagement_dict, monkeypatch):
        http = self._web(tmp_path, minimal_engagement_dict, monkeypatch)
        with pytest.raises(PermissionError):
            await http.handler(url="https://staging.example.com/x", method="DELETE")

    async def test_read_method_allowed_by_default(self, tmp_path, minimal_engagement_dict, monkeypatch):
        http = self._web(tmp_path, minimal_engagement_dict, monkeypatch)
        res = await http.handler(url="https://staging.example.com/x", method="GET")
        assert res["status"] == 200

    async def test_write_method_allowed_when_opted_in(self, tmp_path, minimal_engagement_dict, monkeypatch):
        d = {**minimal_engagement_dict, "scope": {**minimal_engagement_dict["scope"], "allow_write_methods": True}}
        http = self._web(tmp_path, d, monkeypatch)
        res = await http.handler(url="https://staging.example.com/x", method="POST")
        assert res["status"] == 200  # passed the gate, no PermissionError


# ---------------------------------------------------------------- RT-12
class TestRT12WindowEnforcement:
    def _orch(self, tmp_path, dict_, start_off_h, end_off_h):
        now = datetime.now(timezone.utc)
        d = {**dict_, "window": {
            "start": (now + timedelta(hours=start_off_h)).isoformat(),
            "end": (now + timedelta(hours=end_off_h)).isoformat(),
        }}
        eng = Engagement.model_validate(d)
        return Orchestrator(eng, engagement_path=tmp_path / "e.yaml",
                            audit_dir=tmp_path / "audit", assets_root=tmp_path)

    async def test_denies_outside_window(self, tmp_path, minimal_engagement_dict):
        orch = self._orch(tmp_path, minimal_engagement_dict, -5, -1)  # window already ended
        assert orch.within_window() is False
        out = await orch._pre_tool_use(
            {"tool_name": "mcp__web__web__http_request",
             "tool_input": {"url": "https://staging.example.com/users"}, "session_id": "s"},
            "tid", None)
        hso = out["hookSpecificOutput"]
        assert hso["permissionDecision"] == "deny"
        assert "window" in hso["permissionDecisionReason"]

    async def test_allows_inside_window(self, tmp_path, minimal_engagement_dict):
        orch = self._orch(tmp_path, minimal_engagement_dict, -1, 1)  # active now
        assert orch.within_window() is True
        out = await orch._pre_tool_use(
            {"tool_name": "mcp__web__web__http_request",
             "tool_input": {"url": "https://staging.example.com/users"}, "session_id": "s"},
            "tid", None)
        assert out == {}  # allowed (no opinion)

    def test_naive_window_rejected_at_parse(self, minimal_engagement_dict):
        # A window without a timezone must be rejected (would otherwise crash
        # covers() at runtime), not silently assumed to be UTC.
        d = {**minimal_engagement_dict, "window": {
            "start": "2026-04-27T09:00:00", "end": "2026-04-27T17:00:00"}}  # no Z
        with pytest.raises(ValueError, match="timezone"):
            Engagement.model_validate(d)

    def test_aware_window_accepted(self, minimal_engagement_dict):
        d = {**minimal_engagement_dict, "window": {
            "start": "2026-04-27T09:00:00Z", "end": "2026-04-27T17:00:00Z"}}
        eng = Engagement.model_validate(d)
        assert eng.window.covers(datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc))


# ---------------------------------------------------------------- RT-13
class TestRT13VerifyFailClosed:
    def _sealed_ledger(self, tmp_path, key):
        w = LedgerWriter(tmp_path / "l.jsonl", hmac_key=key)
        w.append({"kind": "session.start"})
        w.append({"kind": "finding.recorded"})
        seal = w.seal()
        return tmp_path / "l.jsonl", seal, w.head_hash

    def test_file_seal_verifies_with_key(self, tmp_path):
        from redteam.ledger.verify import verify
        key = b"k" * 32
        ledger, seal, _ = self._sealed_ledger(tmp_path, key)
        assert verify(ledger, seal, key) == 0

    def test_file_seal_fails_closed_without_key(self, tmp_path):
        from redteam.ledger.verify import verify
        ledger, seal, _ = self._sealed_ledger(tmp_path, b"k" * 32)
        rc = verify(ledger, seal, None)  # the documented `redteam-verify <ledger> <seal>` form
        assert rc != 0, "a seal present but unverifiable must NOT exit 0"

    def test_wrong_key_fails(self, tmp_path):
        from redteam.ledger.verify import verify
        ledger, seal, _ = self._sealed_ledger(tmp_path, b"k" * 32)
        assert verify(ledger, seal, b"WRONG" * 8) == 6

    def test_chain_only_check_passes_without_seal(self, tmp_path):
        from redteam.ledger.verify import verify
        ledger, _, _ = self._sealed_ledger(tmp_path, b"k" * 32)
        assert verify(ledger, None, None) == 0  # chain integrity only

    def test_kms_seal_dispatches_and_fails_closed(self, tmp_path, monkeypatch):
        from redteam.ledger.verify import verify
        import redteam.ledger.kms_seal as kms
        ledger, _, head = self._sealed_ledger(tmp_path, b"k" * 32)
        kms_seal = tmp_path / "k.seal"
        kms_seal.write_text(json.dumps({
            "ledger": "l.jsonl", "head_hash": head, "entry_count": 2, "method": "kms",
            "kms_key_arn": "arn:aws:kms:us-east-1:1:key/x", "kms_region": "us-east-1",
            "mac_algorithm": "HMAC_SHA_256", "mac": "deadbeef",
        }))
        def boom(self, h, s): raise RuntimeError("no AWS credentials")
        monkeypatch.setattr(kms.KmsHmacSealer, "verify", boom)
        assert verify(ledger, kms_seal, None) == 8  # KMS unverifiable → non-zero

    def test_kms_seal_dispatches_and_passes(self, tmp_path, monkeypatch):
        from redteam.ledger.verify import verify
        import redteam.ledger.kms_seal as kms
        ledger, _, head = self._sealed_ledger(tmp_path, b"k" * 32)
        kms_seal = tmp_path / "k.seal"
        kms_seal.write_text(json.dumps({
            "ledger": "l.jsonl", "head_hash": head, "entry_count": 2, "method": "kms",
            "kms_key_arn": "arn:x", "kms_region": "us-east-1",
            "mac_algorithm": "HMAC_SHA_256", "mac": "deadbeef",
        }))
        monkeypatch.setattr(kms.KmsHmacSealer, "verify", lambda self, h, s: True)
        assert verify(ledger, kms_seal, None) == 0


# ---------------------------------------------------------------- RT-15
class TestRT15SubagentToolScoping:
    def test_exploiter_restricted_to_its_tool_subset(self, tmp_path, minimal_engagement_dict):
        d = {**minimal_engagement_dict, "tools": ["recon", "web", "report"],
             "subagents": ["recon", "exploiter"]}
        eng = Engagement.model_validate(d)
        orch = Orchestrator(eng, engagement_path=tmp_path / "e.yaml",
                            audit_dir=tmp_path / "audit", assets_root=tmp_path)
        agents = orch.build_options()["agents"]
        ex = agents["exploiter"]
        # the dangerous subagent is restricted to web + report, mapped to SDK names
        assert ex.tools == ["mcp__web__web__http_request", "mcp__report__report__write_finding"]
        assert ex.prompt.lstrip().startswith("You are the exploiter")  # frontmatter stripped

    def test_every_subagent_gets_a_scoped_tool_list(self, tmp_path, minimal_engagement_dict):
        d = {**minimal_engagement_dict, "tools": ["recon", "web", "report"],
             "subagents": ["recon", "analyst", "exploiter"]}
        eng = Engagement.model_validate(d)
        orch = Orchestrator(eng, engagement_path=tmp_path / "e.yaml",
                            audit_dir=tmp_path / "audit", assets_root=tmp_path)
        agents = orch.build_options()["agents"]
        for name, ad in agents.items():
            assert ad.tools, f"{name} must have an explicit (non-empty) tool subset"
            assert all(t.startswith("mcp__") for t in ad.tools), ad.tools

    def test_tool_mapping_least_privilege_edge_cases(self):
        from redteam.orchestrator import _map_subagent_tools

        # absent / null -> None (inherit the SDK default)
        assert _map_subagent_tools({}) is None
        assert _map_subagent_tools({"tools": None}) is None
        # explicit empty list -> [] (ZERO tools), NOT None (the RT-15 bug)
        assert _map_subagent_tools({"tools": []}) == []
        # a real list maps to SDK names
        assert _map_subagent_tools({"tools": ["web__http_request"]}) == [
            "mcp__web__web__http_request"]
        # malformed (string / dict) fails closed to zero tools, never inherit-all
        assert _map_subagent_tools({"tools": "web__http_request"}) == []
        assert _map_subagent_tools({"tools": {"a": "b"}}) == []
