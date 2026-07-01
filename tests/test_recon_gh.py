"""recon gh_* tools (build-next #4): read-only, org-scoped `gh` CLI wrappers.

The tools shell out to `gh` via a list argv (never a shell) and must:
degrade to a structured error (never crash) when gh is missing / errors /
times out / returns non-JSON; refuse flag-like or malformed owner/repo/query
(argument-injection guard); and be treated as targetless by the scope guard.
Every test mocks the subprocess — no real `gh` call, no network, no auth.
"""

from __future__ import annotations

import subprocess

import pytest

from redteam.engagement import Engagement
from redteam.hooks.scope_guard import ScopeGuard
from redteam.tools import recon
from redteam.tools._context import ToolContext


@pytest.fixture
def ctx(minimal_engagement_dict) -> ToolContext:
    from redteam.assets import build_index
    from redteam.hooks.audit_writer import AuditWriter
    from redteam.ledger.chain import LedgerWriter

    eng = Engagement.model_validate(minimal_engagement_dict)
    return ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter("/tmp/redteam-test-unused.jsonl")),
        assets=build_index(eng.assets, host_root=None, require_exists=False),
        audit_dir=None,  # type: ignore[arg-type]
    )


def _tools(ctx: ToolContext, monkeypatch) -> dict:
    # Capture the registered tools regardless of whether the real SDK is
    # installed (matches tests/test_m1_tool_sdk_contract.py).
    cap: dict = {}
    monkeypatch.setattr(
        recon, "create_sdk_mcp_server", lambda name, version, tools: cap.update(t=tools)
    )
    recon.build_pack(ctx)
    return {t.name: t for t in cap["t"]}


def _fake_run(returncode=0, stdout="[]", stderr=""):
    def run(argv, **kwargs):
        run.calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    run.calls = []
    return run


def _patch_gh(monkeypatch, run, gh_bin="/usr/bin/gh"):
    monkeypatch.setattr(recon.shutil, "which", lambda name: gh_bin)
    monkeypatch.setattr(recon.subprocess, "run", run)


# ---- argv building + JSON parsing ------------------------------------------


async def test_gh_search_code_builds_argv_and_parses(ctx, monkeypatch) -> None:
    run = _fake_run(stdout='[{"path": "app/db.py", "repository": {"nameWithOwner": "acme/api"}}]')
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query="password", owner="acme", limit=5)

    argv = run.calls[0]
    assert argv[0] == "/usr/bin/gh"
    assert argv[1:3] == ["search", "code"]
    assert "password" in argv and "--owner" in argv and "acme" in argv
    assert argv[argv.index("--limit") + 1] == "5"
    assert res["status"] == "ok"
    assert res["count"] == 1
    assert res["results"][0]["path"] == "app/db.py"


async def test_gh_search_repos_owner_scoped(ctx, monkeypatch) -> None:
    run = _fake_run(stdout='[{"fullName": "acme/api", "visibility": "private"}]')
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_repos"].handler(owner="acme", query="payments")

    argv = run.calls[0]
    assert argv[1:3] == ["search", "repos"]
    assert argv[argv.index("--owner") + 1] == "acme"
    assert res["status"] == "ok" and res["results"][0]["fullName"] == "acme/api"


async def test_gh_repo_view_builds_argv(ctx, monkeypatch) -> None:
    run = _fake_run(stdout='{"name": "api", "visibility": "private"}')
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_repo_view"].handler(repo="acme/api")

    argv = run.calls[0]
    assert argv[1:3] == ["repo", "view"]
    assert argv[3] == "acme/api"
    assert "--json" in argv
    assert res["status"] == "ok" and res["repo"]["name"] == "api"


# ---- degrade-never-crash ----------------------------------------------------


async def test_gh_missing_binary_returns_error(ctx, monkeypatch) -> None:
    monkeypatch.setattr(recon.shutil, "which", lambda name: None)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query="x", owner="acme")
    assert res["status"] == "error" and "not found" in res["error"].lower()


async def test_gh_nonzero_exit_returns_error(ctx, monkeypatch) -> None:
    run = _fake_run(returncode=1, stdout="", stderr="gh: HTTP 403")
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query="x", owner="acme")
    assert res["status"] == "error" and res["exit_code"] == 1 and "403" in res["stderr"]


async def test_gh_timeout_returns_error(ctx, monkeypatch) -> None:
    def run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 30))

    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_repo_view"].handler(repo="acme/api")
    assert res["status"] == "error" and "tim" in res["error"].lower()


async def test_gh_invalid_json_returns_error(ctx, monkeypatch) -> None:
    run = _fake_run(stdout="not json at all")
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query="x", owner="acme")
    assert res["status"] == "error" and "json" in res["error"].lower()


# ---- argument-injection guard (must not even invoke gh) --------------------


@pytest.mark.parametrize(
    "tool,kwargs",
    [
        ("recon__gh_search_code", {"query": "x", "owner": "--version"}),
        ("recon__gh_search_code", {"query": "-X", "owner": "acme"}),
        ("recon__gh_search_repos", {"owner": "acme; rm -rf /"}),
        ("recon__gh_repo_view", {"repo": "--help"}),
        ("recon__gh_repo_view", {"repo": "not-a-repo"}),
    ],
)
async def test_gh_rejects_flaglike_or_malformed_input(ctx, monkeypatch, tool, kwargs) -> None:
    run = _fake_run()
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)[tool].handler(**kwargs)
    assert res["status"] == "error"
    assert run.calls == [], "gh must NOT be invoked for a rejected argument"


# ---- containment: query qualifiers, owner allowlist, safe limit ------------


def _ctx_with_orgs(minimal_engagement_dict, orgs) -> ToolContext:
    from redteam.assets import build_index
    from redteam.hooks.audit_writer import AuditWriter
    from redteam.ledger.chain import LedgerWriter

    d = {**minimal_engagement_dict, "scope": {**minimal_engagement_dict["scope"], "github_orgs": orgs}}
    eng = Engagement.model_validate(d)
    return ToolContext(
        engagement=eng,
        scope=ScopeGuard(eng),
        audit=AuditWriter(LedgerWriter("/tmp/redteam-test-unused.jsonl")),
        assets=build_index(eng.assets, host_root=None, require_exists=False),
        audit_dir=None,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("bad_query", ["secret org:victim", "x user:someone", "y repo:acme/other"])
async def test_gh_search_rejects_scope_broadening_qualifiers(ctx, monkeypatch, bad_query) -> None:
    run = _fake_run()
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query=bad_query, owner="acme")
    assert res["status"] == "error"
    assert run.calls == [], "a scope-broadening query qualifier must be refused before gh runs"


async def test_gh_owner_allowlist_enforced_when_set(minimal_engagement_dict, monkeypatch) -> None:
    ctx = _ctx_with_orgs(minimal_engagement_dict, ["acme"])
    run = _fake_run(stdout="[]")
    _patch_gh(monkeypatch, run)
    tools = _tools(ctx, monkeypatch)

    denied = await tools["recon__gh_search_code"].handler(query="x", owner="victim")
    assert denied["status"] == "error" and run.calls == []

    ok = await tools["recon__gh_search_code"].handler(query="x", owner="acme")
    assert ok["status"] == "ok" and len(run.calls) == 1


async def test_gh_owner_allowlist_empty_allows_any_owner(ctx, monkeypatch) -> None:
    # Default (no github_orgs configured): any owner permitted (PAT-bound).
    run = _fake_run(stdout="[]")
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query="x", owner="whatever")
    assert res["status"] == "ok" and len(run.calls) == 1


async def test_gh_repo_view_honours_owner_allowlist(minimal_engagement_dict, monkeypatch) -> None:
    ctx = _ctx_with_orgs(minimal_engagement_dict, ["acme"])
    run = _fake_run(stdout='{"name": "api"}')
    _patch_gh(monkeypatch, run)
    tools = _tools(ctx, monkeypatch)

    denied = await tools["recon__gh_repo_view"].handler(repo="victim/api")
    assert denied["status"] == "error" and run.calls == []

    ok = await tools["recon__gh_repo_view"].handler(repo="acme/api")
    assert ok["status"] == "ok" and len(run.calls) == 1


async def test_gh_limit_non_integer_returns_error(ctx, monkeypatch) -> None:
    run = _fake_run()
    _patch_gh(monkeypatch, run)
    res = await _tools(ctx, monkeypatch)["recon__gh_search_code"].handler(query="x", owner="acme", limit="abc")
    assert res["status"] == "error" and run.calls == []


def test_owner_and_repo_regex_reject_trailing_newline() -> None:
    assert recon._OWNER_RE.match("acme\n") is None
    assert recon._REPO_RE.match("acme/api\n") is None
    assert recon._OWNER_RE.match("acme") and recon._REPO_RE.match("acme/api")


def test_scope_github_orgs_validation(minimal_engagement_dict) -> None:
    from pydantic import ValidationError

    def _with(orgs):
        return {**minimal_engagement_dict, "scope": {**minimal_engagement_dict["scope"], "github_orgs": orgs}}

    Engagement.model_validate(_with(["acme", "my-org"]))  # valid logins accepted
    for bad in ["-bad", "acme/api", "has space", "", "trailing-"]:
        with pytest.raises(ValidationError):
            Engagement.model_validate(_with([bad]))


# ---- scope guard treats gh_* as targetless ---------------------------------


def test_gh_tools_are_targetless(minimal_engagement_dict) -> None:
    eng = Engagement.model_validate(minimal_engagement_dict)
    g = ScopeGuard(eng)
    for name in ("recon__gh_search_code", "recon__gh_search_repos", "recon__gh_repo_view"):
        # As delivered by the SDK (mcp__<server>__<tool>) and bare.
        assert g.check(f"mcp__recon__{name}", {"query": "x", "owner": "acme"}).allowed
        assert g.check(name, {"repo": "acme/api"}).allowed
