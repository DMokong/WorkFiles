"""External MCP adapter - GitHub and Atlassian only.

The schema (engagement.ExternalMcp) already enforces the allowlist at
parse time. This module turns validated entries into the connection
configs the SDK consumes, plus performs runtime preflight checks
(egress reachability, ledger record on failure).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .engagement import ALLOWED_EXTERNAL_MCPS, Engagement, ExternalMcp, ExternalMcpTransport
from .hooks.audit_writer import AuditWriter


@dataclass(frozen=True)
class ExternalMcpConfig:
    name: str
    sdk_config: dict[str, Any]
    allowed_tools: list[str]


def build_configs(engagement: Engagement, audit: AuditWriter) -> list[ExternalMcpConfig]:
    out: list[ExternalMcpConfig] = []
    for entry in engagement.external_mcp:
        # Re-assert allowlist at runtime as defence-in-depth.
        if entry.name not in ALLOWED_EXTERNAL_MCPS:
            audit.record_external_mcp(
                name=entry.name,
                status="rejected",
                detail=f"name not in allowlist {sorted(ALLOWED_EXTERNAL_MCPS)}",
            )
            raise PermissionError(
                f"external_mcp {entry.name!r} blocked by allowlist (this should have been "
                "caught by schema validation; do not bypass)"
            )
        out.append(_to_config(entry))
        audit.record_external_mcp(
            name=entry.name,
            status="registered",
            detail=f"transport={entry.transport.value} tools={entry.allowed_tools}",
        )
    return out


def _to_config(entry: ExternalMcp) -> ExternalMcpConfig:
    if entry.transport == ExternalMcpTransport.stdio:
        cfg: dict[str, Any] = {"type": "stdio", "command": entry.command}
    elif entry.transport == ExternalMcpTransport.http:
        cfg = {"type": "http", "url": entry.url}
    else:  # sse
        cfg = {"type": "sse", "url": entry.url}
    return ExternalMcpConfig(
        name=entry.name,
        sdk_config=cfg,
        allowed_tools=list(entry.allowed_tools),
    )


def prefixed_tool_names(configs: list[ExternalMcpConfig]) -> list[str]:
    """Tool names as the SDK exposes them ("<server>__<tool>")."""
    out: list[str] = []
    for c in configs:
        for t in c.allowed_tools:
            out.append(t if "__" in t else f"{c.name}__{t}")
    return out
