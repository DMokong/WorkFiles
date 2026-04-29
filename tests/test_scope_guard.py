"""Scope-guard contract: in-scope allowed, out-of-scope denied, deny wins."""

from __future__ import annotations

from redteam.engagement import Engagement
from redteam.hooks.scope_guard import ScopeGuard


def _engagement(minimal_engagement_dict: dict, **overrides) -> Engagement:
    minimal_engagement_dict["scope"] = {**minimal_engagement_dict["scope"], **overrides}
    return Engagement.model_validate(minimal_engagement_dict)


def test_in_scope_url_allowed(minimal_engagement_dict: dict) -> None:
    eng = _engagement(minimal_engagement_dict)
    g = ScopeGuard(eng)
    decision = g.check("recon__dns_lookup", {"host": "staging.example.com"})
    assert decision.allowed, decision.reason


def test_out_of_scope_path_denied(minimal_engagement_dict: dict) -> None:
    eng = _engagement(
        minimal_engagement_dict,
        out_of_scope=["https://staging.example.com/admin"],
    )
    g = ScopeGuard(eng)
    decision = g.check("web__http_request", {"url": "https://staging.example.com/admin/users"})
    assert not decision.allowed
    assert "out_of_scope" in decision.reason


def test_unknown_target_denied(minimal_engagement_dict: dict) -> None:
    eng = _engagement(minimal_engagement_dict)
    g = ScopeGuard(eng)
    decision = g.check("web__http_request", {"url": "https://evil.example.net/"})
    assert not decision.allowed
    assert "not in scope" in decision.reason


def test_targetless_tool_allowed(minimal_engagement_dict: dict) -> None:
    eng = _engagement(minimal_engagement_dict)
    g = ScopeGuard(eng)
    decision = g.check("report__write_finding", {})
    assert decision.allowed
