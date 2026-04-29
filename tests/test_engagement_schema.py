"""Schema tests for the engagement YAML pydantic model.

Specifies the contract that the next implementation phase must keep:
the schema is the only thing parsing the YAML, every gate downstream
reads from a parsed Engagement.
"""

from __future__ import annotations

import pytest

from redteam.engagement import ALLOWED_EXTERNAL_MCPS, Engagement


def test_minimal_engagement_parses(minimal_engagement_dict: dict) -> None:
    eng = Engagement.model_validate(minimal_engagement_dict)
    assert eng.id == "ENG-TEST-001"
    assert eng.budget.max_turns == 50


def test_external_mcp_allowlist_is_atlassian_only() -> None:
    assert ALLOWED_EXTERNAL_MCPS == frozenset({"atlassian"})


def test_external_mcp_rejects_unknown(minimal_engagement_dict: dict) -> None:
    minimal_engagement_dict["external_mcp"] = [
        {
            "name": "burp",
            "transport": "stdio",
            "command": ["burp-mcp"],
            "allowed_tools": ["burp__scan"],
        }
    ]
    with pytest.raises(ValueError, match="not in allowlist"):
        Engagement.model_validate(minimal_engagement_dict)


def test_external_mcp_rejects_github_now_that_it_is_via_gh_cli(minimal_engagement_dict: dict) -> None:
    minimal_engagement_dict["external_mcp"] = [
        {
            "name": "github",
            "transport": "http",
            "url": "https://api.githubcopilot.com/mcp/",
            "allowed_tools": ["github__search_code"],
        }
    ]
    with pytest.raises(ValueError, match="not in allowlist"):
        Engagement.model_validate(minimal_engagement_dict)


def test_whitebox_requires_assets(minimal_engagement_dict: dict) -> None:
    minimal_engagement_dict["tools"] = ["recon", "whitebox", "report"]
    with pytest.raises(ValueError, match="whitebox.*assets"):
        Engagement.model_validate(minimal_engagement_dict)


def test_window_must_be_ordered(minimal_engagement_dict: dict) -> None:
    minimal_engagement_dict["window"] = {
        "start": "2030-01-02T00:00:00Z",
        "end": "2030-01-01T00:00:00Z",
    }
    with pytest.raises(ValueError, match="window.end must be after"):
        Engagement.model_validate(minimal_engagement_dict)
