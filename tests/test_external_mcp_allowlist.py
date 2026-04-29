"""External MCP must be Atlassian-only; everything else is rejected."""

from __future__ import annotations

import pytest

from redteam.engagement import Engagement


def test_atlassian_accepted(minimal_engagement_dict: dict) -> None:
    minimal_engagement_dict["scope"]["egress_allowlist"].append("mcp.atlassian.com")
    minimal_engagement_dict["external_mcp"] = [
        {
            "name": "atlassian",
            "transport": "http",
            "url": "https://mcp.atlassian.com/v1/sse",
            "allowed_tools": ["jira__search", "jira__create_issue"],
        }
    ]
    eng = Engagement.model_validate(minimal_engagement_dict)
    assert eng.external_mcp[0].name == "atlassian"


@pytest.mark.parametrize("name", ["github", "gitlab", "burp", "shodan", "Atlassian"])
def test_other_names_rejected(minimal_engagement_dict: dict, name: str) -> None:
    minimal_engagement_dict["external_mcp"] = [
        {
            "name": name,
            "transport": "http",
            "url": f"https://mcp.{name}.example/",
            "allowed_tools": ["x__y"],
        }
    ]
    with pytest.raises(ValueError):
        Engagement.model_validate(minimal_engagement_dict)


def test_atlassian_host_must_be_in_egress_allowlist(minimal_engagement_dict: dict) -> None:
    # mcp.atlassian.com is NOT in egress_allowlist here.
    minimal_engagement_dict["external_mcp"] = [
        {
            "name": "atlassian",
            "transport": "http",
            "url": "https://mcp.atlassian.com/v1/sse",
            "allowed_tools": ["jira__search"],
        }
    ]
    with pytest.raises(ValueError, match="egress_allowlist"):
        Engagement.model_validate(minimal_engagement_dict)
