"""SDK shim - lets the package import cleanly when claude-agent-sdk is absent.

Tool implementations stay testable without the SDK installed; the shim only
matters at orchestrator wiring time.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass, field
from typing import Any, Callable


def _as_mcp_content(raw: Any) -> dict[str, Any]:
    """Wrap a tool's return value in the MCP ``{"content": [...]}`` shape the SDK
    requires (a bare dict yields empty content to the model)."""
    if isinstance(raw, dict) and "content" in raw:
        return raw
    return {"content": [{"type": "text", "text": json.dumps(raw, default=str)}]}


try:
    from claude_agent_sdk import (
        AgentDefinition,
        HookMatcher,
        create_sdk_mcp_server,
    )
    from claude_agent_sdk import tool as _sdk_tool

    HAS_SDK = True

    def tool(name: str, description: str, input_schema: Any = None):  # type: ignore[no-redef]
        """Register an in-process MCP tool, adapting our calling convention.

        The SDK invokes a tool handler with a SINGLE arguments dict and expects
        ``{"content": [...]}`` back. Our tool bodies are written with unpacked
        params returning a raw dict (and the unit tests call ``.handler(**kwargs)``
        and assert on that raw dict). This wrapper bridges both: a single-dict
        call (the SDK) is unpacked into the body and the result re-wrapped as MCP
        content; a kwargs call (direct/tests) passes through and returns raw.
        """

        def decorator(fn: Callable[..., Any]) -> Any:
            @functools.wraps(fn)
            async def handler(args: Any = None, **kwargs: Any) -> Any:
                if isinstance(args, dict):  # SDK convention: one positional dict
                    return _as_mcp_content(await fn(**args))
                return await fn(**kwargs)  # direct/test convention: raw dict out

            return _sdk_tool(name, description, input_schema or {})(handler)

        return decorator

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
