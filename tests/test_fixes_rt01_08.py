"""Regression tests for review findings RT-01..RT-08.

Each test pins a behaviour that was broken (or absent) before the fix and that
the current test suite did not cover. See docs/REVIEW.md.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from redteam.engagement import Engagement
from redteam.hooks.scope_guard import ScopeGuard, _strip_mcp_prefix


def _guard(minimal_engagement_dict: dict, **scope_overrides) -> ScopeGuard:
    minimal_engagement_dict["scope"] = {**minimal_engagement_dict["scope"], **scope_overrides}
    return ScopeGuard(Engagement.model_validate(minimal_engagement_dict))


# ---------------------------------------------------------------- RT-06
class TestRT06UrlCanonicalization:
    @pytest.mark.parametrize(
        "url",
        [
            "https://staging.example.com/admin",            # exact
            "https://staging.example.com/admin/users",      # under prefix
            "https://staging.example.com/%61dmin",          # percent-encoded 'a'
            "https://staging.example.com/%2561dmin",        # double-encoded
            "https://staging.example.com//admin",           # duplicate slash
            "https://staging.example.com/./admin",          # dot segment
            "https://staging.example.com/foo/../admin",     # parent traversal
            "https://staging.example.com/ADMIN",            # case
            "https://staging.example.com/admin.",           # trailing dot (Apache/IIS)
            "https://staging.example.com/admin%2e",         # encoded trailing dot
            "https://staging.example.com/admin;x=y",        # path parameter
            "https://staging.example.com/admin%3bx=y",      # encoded path parameter
            "https://staging.example.com/admin%00.html",    # null-byte truncation
            "https://staging.example.com/foo\\..\\admin",   # backslash path separator
            "https://staging.example.com/admin/",           # trailing slash
        ],
    )
    def test_out_of_scope_admin_cannot_be_bypassed(self, minimal_engagement_dict, url):
        g = _guard(minimal_engagement_dict, out_of_scope=["https://staging.example.com/admin"])
        decision = g.check("web__http_request", {"url": url})
        assert not decision.allowed, f"{url} should be denied by out_of_scope /admin"
        assert "out_of_scope" in decision.reason

    def test_non_admin_path_still_allowed(self, minimal_engagement_dict):
        g = _guard(minimal_engagement_dict, out_of_scope=["https://staging.example.com/admin"])
        decision = g.check("web__http_request", {"url": "https://staging.example.com/public"})
        assert decision.allowed, decision.reason


# ---------------------------------------------------------------- RT-07
class TestRT07EmptyEgress:
    def test_empty_egress_denies_off_target_host(self, minimal_engagement_dict):
        g = _guard(
            minimal_engagement_dict,
            targets=["https://staging.example.com"],
            egress_allowlist=[],
        )
        # An in-scope-looking but different host must not slip through when the
        # allowlist is empty (previously empty list short-circuited the check).
        decision = g.check("web__http_request", {"url": "https://evil.example.net/"})
        assert not decision.allowed

    def test_empty_egress_still_allows_target_host(self, minimal_engagement_dict):
        g = _guard(
            minimal_engagement_dict,
            targets=["https://staging.example.com"],
            egress_allowlist=[],
        )
        decision = g.check("web__http_request", {"url": "https://staging.example.com/x"})
        assert decision.allowed, decision.reason


# ---------------------------------------------------------------- RT-05
class TestRT05ToolNamePrefix:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("mcp__whitebox__whitebox__repo_read", "whitebox__repo_read"),
            ("mcp__atlassian__jira__search", "jira__search"),
            ("report__write_finding", "report__write_finding"),
            ("web__http_request", "web__http_request"),
        ],
    )
    def test_strip_mcp_prefix(self, raw, expected):
        assert _strip_mcp_prefix(raw) == expected

    def test_sdk_prefixed_targetless_tool_allowed(self, minimal_engagement_dict):
        g = _guard(minimal_engagement_dict)
        # The SDK delivers in-process MCP tool names double-prefixed.
        decision = g.check("mcp__whitebox__whitebox__repo_read", {})
        assert decision.allowed, decision.reason

    def test_sdk_prefixed_unknown_targetless_denied(self, minimal_engagement_dict):
        g = _guard(minimal_engagement_dict)
        decision = g.check("mcp__web__web__http_request", {})  # needs a target
        assert not decision.allowed


# ---------------------------------------------------------------- RT-02 / RT-03
class TestRT02DryRun:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "redteam.cli", *args],
            capture_output=True,
            text=True,
        )

    def test_dry_run_creates_no_audit_dir_and_succeeds(self, tmp_path, repo_root):
        # Point --audit-dir at a path that does NOT exist; --dry-run must not
        # create it (or any other file) and must exit 0.
        audit = tmp_path / "should-not-be-created"
        eng = repo_root / "engagements" / "example.yaml"
        proc = self._run(
            "run", str(eng), "--dry-run",
            "--audit-dir", str(audit),
            "--assets-root", str(repo_root),
        )
        assert proc.returncode == 0, proc.stderr
        assert not audit.exists(), "dry-run must not create the audit dir"
        assert "Allowed tools" in proc.stdout


# ---------------------------------------------------------------- RT-01
class TestRT01NoRedirect:
    def test_web_pack_uses_non_redirecting_opener(self):
        # The web pack must build an opener that does not auto-follow redirects,
        # so an in-scope URL cannot bounce the agent to an out-of-scope host
        # (e.g. the cloud metadata endpoint) without a fresh scope check.
        import redteam.tools.web as web

        assert hasattr(web, "_build_no_redirect_opener")
        opener = web._build_no_redirect_opener()
        handlers = [type(h).__name__ for h in opener.handlers]
        assert any("NoRedirect" in h or "_NoRedirect" in h for h in handlers), handlers


def test_netpolicy_does_not_allow_imds():
    repo = Path(__file__).resolve().parent.parent
    pol = json.loads((repo / "redteam" / "runtime" / "netpolicy.json").read_text())
    assert "169.254.169.254" not in pol.get("always_allow", []), (
        "the cloud metadata endpoint must not be agent-reachable (RT-01)"
    )


# ---------------------------------------------------------------- RT-04
class TestRT04SdkSeam:
    def _orch(self, repo_root):
        from redteam.engagement import Engagement
        from redteam.orchestrator import Orchestrator

        eng = Engagement.from_yaml(repo_root / "engagements" / "example.yaml")
        return Orchestrator(
            engagement=eng,
            engagement_path=(repo_root / "engagements" / "example.yaml"),
            audit_dir=Path("/tmp/redteam-test-audit-unused"),
            assets_root=repo_root,
        )

    def test_build_options_constructs_real_sdk_options(self, repo_root):
        sdk = pytest.importorskip("claude_agent_sdk")
        orch = self._orch(repo_root)
        options = orch.build_options()
        # The whole point of RT-04: this must not raise.
        sdk.ClaudeAgentOptions(**options)

    def test_hooks_are_hookmatchers_without_session_events(self, repo_root):
        sdk = pytest.importorskip("claude_agent_sdk")
        orch = self._orch(repo_root)
        hooks = orch.build_options()["hooks"]
        assert set(hooks) == {"PreToolUse", "PostToolUse"}  # no SessionStart/End
        for matchers in hooks.values():
            assert all(isinstance(m, sdk.HookMatcher) for m in matchers)

    def test_agents_are_agent_definitions_with_clean_prompt(self, repo_root):
        sdk = pytest.importorskip("claude_agent_sdk")
        orch = self._orch(repo_root)
        agents = orch.build_options()["agents"]
        assert agents, "example.yaml declares subagents"
        for name, ad in agents.items():
            assert isinstance(ad, sdk.AgentDefinition)
            assert not ad.prompt.lstrip().startswith("---"), "frontmatter must be stripped"
            assert ad.description

    def test_allowed_tools_use_mcp_prefix(self, repo_root):
        orch = self._orch(repo_root)
        allowed = orch.build_options()["allowed_tools"]
        assert any(a.startswith("mcp__") for a in allowed), allowed
        assert "recon__*" not in allowed  # old broken wildcard is gone

    async def test_pre_tool_use_denies_out_of_scope_in_sdk_shape(self, repo_root):
        orch = self._orch(repo_root)
        out = await orch._pre_tool_use(
            {"tool_name": "mcp__web__web__http_request",
             "tool_input": {"url": "https://evil.example.net/"},
             "session_id": "s"},
            "tool-use-1",
            None,
        )
        hso = out["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["permissionDecision"] == "deny"


# ---------------------------------------------------------------- RT-08
import shutil  # noqa: E402

_HAS_SSH = shutil.which("ssh-keygen") is not None


def test_no_embedded_signature_field():
    # The chicken-and-egg embedded field is gone from the schema.
    assert "operator_signature" not in Engagement.model_fields


@pytest.mark.skipif(not _HAS_SSH, reason="ssh-keygen not on PATH")
class TestRT08DetachedSignature:
    NS = "redteam-engagement"

    def _setup(self, tmp_path, principal="tester@example.com"):
        key = tmp_path / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"], check=True
        )
        pub = (tmp_path / "id_ed25519.pub").read_text().strip()
        signers = tmp_path / "authorized_signers"
        signers.write_text(f'{principal} namespaces="{self.NS}" {pub}\n')
        eng = tmp_path / "eng.yaml"
        eng.write_text("id: ENG-X\nobjective: pin the detached-signature flow end to end ok\n")
        return key, signers, eng

    def _sign(self, key, eng):
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", self.NS, str(eng)],
            check=True,
            capture_output=True,
        )

    def test_valid_detached_signature_verifies(self, tmp_path):
        from redteam.auth import verify_engagement_file

        key, signers, eng = self._setup(tmp_path)
        self._sign(key, eng)
        res = verify_engagement_file(eng, "tester@example.com", allowed_signers=signers, namespace=self.NS)
        assert res.ok, res.detail

    def test_tampered_body_rejected(self, tmp_path):
        from redteam.auth import verify_engagement_file

        key, signers, eng = self._setup(tmp_path)
        self._sign(key, eng)
        eng.write_text(eng.read_text() + "\n# tampered after signing\n")
        res = verify_engagement_file(eng, "tester@example.com", allowed_signers=signers, namespace=self.NS)
        assert not res.ok

    def test_missing_sidecar_rejected(self, tmp_path):
        from redteam.auth import verify_engagement_file

        _, signers, eng = self._setup(tmp_path)  # never signed
        res = verify_engagement_file(eng, "tester@example.com", allowed_signers=signers, namespace=self.NS)
        assert not res.ok
        assert "not found" in res.detail

    def test_wrong_principal_rejected(self, tmp_path):
        from redteam.auth import verify_engagement_file

        key, signers, eng = self._setup(tmp_path, principal="tester@example.com")
        self._sign(key, eng)
        # Signed by tester@, but claim mallory@ as operator -> rejected.
        res = verify_engagement_file(eng, "mallory@example.com", allowed_signers=signers, namespace=self.NS)
        assert not res.ok


class TestRT08CliEnforcement:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "redteam.cli", *args], capture_output=True, text=True
        )

    def test_real_run_refuses_unsigned_engagement(self, repo_root, tmp_path):
        # No .sig sidecar -> a real run must refuse with a non-zero exit.
        proc = self._run(
            "run", str(repo_root / "engagements" / "example.yaml"),
            "--audit-dir", str(tmp_path / "audit"),
            "--assets-root", str(repo_root),
        )
        assert proc.returncode != 0
        assert "REFUSED" in proc.stderr or "signature" in proc.stderr.lower()
        assert not (tmp_path / "audit").exists(), "must refuse before writing audit"

    def test_dry_run_does_not_require_signature(self, repo_root, tmp_path):
        proc = self._run(
            "run", str(repo_root / "engagements" / "example.yaml"), "--dry-run",
            "--audit-dir", str(tmp_path / "audit"),
            "--assets-root", str(repo_root),
        )
        assert proc.returncode == 0, proc.stderr
