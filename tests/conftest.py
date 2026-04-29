"""Shared fixtures for the redteam test suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from textwrap import dedent

import pytest


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture
def example_engagement_yaml(repo_root: Path) -> Path:
    return repo_root / "engagements" / "example.yaml"


@pytest.fixture
def minimal_engagement_dict() -> dict:
    """A minimal-but-valid engagement, sans operator signature.

    Used for schema/scope tests that don't need a real signature.
    """
    now = datetime.now(timezone.utc)
    return {
        "id": "ENG-TEST-001",
        "operator": "tester@example.com",
        "authorized_by": "ciso@example.com",
        "window": {
            "start": now.isoformat(),
            "end": (now + timedelta(hours=1)).isoformat(),
        },
        "scope": {
            "targets": ["https://staging.example.com"],
            "egress_allowlist": ["staging.example.com", "api.anthropic.com"],
        },
        "budget": {
            "max_turns": 50,
            "max_usd": 5.0,
            "max_tool_calls_per_target": 20,
        },
        "tools": ["recon", "report"],
        "objective": dedent(
            """
            Pytest fixture engagement; no real targets. Used to exercise
            schema parsing and scope-guard behaviour in unit tests only.
            """
        ).strip(),
    }
