"""SDK shim - lets the package import cleanly when claude-agent-sdk is absent.

Tool implementations stay testable without the SDK installed; the shim only
matters at orchestrator wiring time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

try:
    from claude_agent_sdk import (
        AgentDefinition,
        HookMatcher,
        create_sdk_mcp_server,
        tool,
    )

    HAS_SDK = True
except ImportError:  # pragma: no cover
    HAS_SDK = False

    def tool(name: str, description: str, input_schema: dict[str, Any] | None = None):  # type: ignore[no-redef]
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            fn._tool_name = name  # type: ignore[attr-defined]
            fn._tool_description = description  # type: ignore[attr-defined]
            fn._tool_input_schema = input_schema or {}  # type: ignore[attr-defined]
            return fn

        return decorator

    def create_sdk_mcp_server(name: str, version: str, tools: list[Callable[..., Any]]):  # type: ignore[no-redef]
        return {"name": name, "version": version, "tools": tools}

    @dataclass
    class HookMatcher:  # type: ignore[no-redef]
        matcher: str | None = None
        hooks: list[Callable[..., Any]] = field(default_factory=list)
        timeout: float | None = None

    @dataclass
    class AgentDefinition:  # type: ignore[no-redef]
        description: str
        prompt: str
        tools: list[str] | None = None


__all__ = [
    "create_sdk_mcp_server",
    "tool",
    "HookMatcher",
    "AgentDefinition",
    "HAS_SDK",
]
