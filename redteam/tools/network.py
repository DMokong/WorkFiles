"""network - TCP connect probe, scope-bound port scan.

Stub pack. Every probe scope-checks against engagement target CIDRs/hosts.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "network"


def build_pack(ctx: ToolContext):
    @tool(
        "network__tcp_connect",
        "Open a TCP connection to (host, port) and report success/timeout. In-scope only.",
        {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "timeout_s": {"type": "number", "default": 3.0},
            },
            "required": ["host", "port"],
        },
    )
    async def tcp_connect(host: str, port: int, timeout_s: float = 3.0) -> dict[str, Any]:
        ctx.assert_in_scope("network__tcp_connect", {"host": host})
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout_s
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return {"host": host, "port": port, "open": True}
        except (asyncio.TimeoutError, OSError) as e:
            return {"host": host, "port": port, "open": False, "error": str(e)}

    @tool(
        "network__port_scan",
        "Stub: lightweight TCP-connect scan of a small port list against an in-scope host.",
        {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "integer"}, "maxItems": 64},
            },
            "required": ["host", "ports"],
        },
    )
    async def port_scan(host: str, ports: list[int]) -> dict[str, Any]:
        ctx.assert_in_scope("network__port_scan", {"host": host})
        results: list[dict[str, Any]] = []
        for p in ports[:64]:
            r = await tcp_connect(host=host, port=p, timeout_s=1.5)  # type: ignore[misc]
            results.append(r)
        return {"host": host, "results": results}

    return create_sdk_mcp_server(
        name="network",
        version="0.1.0",
        tools=[tcp_connect, port_scan],
    )
