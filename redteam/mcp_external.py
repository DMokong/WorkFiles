"""External MCP adapter - Atlassian Rovo only.

The schema (engagement.ExternalMcp) already enforces the allowlist at
parse time. This module turns validated entries into the connection
configs the SDK consumes, plus performs runtime preflight checks
(egress reachability, ledger record on failure).

GitHub is intentionally *not* an MCP dependency: recon and asset-fetch
use the `gh` CLI baked into the runtime image, authenticated via a PAT
mounted at /run/secrets/gh_token. See redteam/tools/recon.py.
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


def build_configs(engagement: Engagement) -> list[ExternalMcpConfig]:
    """Pure: validate + build SDK configs for the allow-listed external MCPs.

    No audit side effects, so this is safe to call from build_options() during a
    --dry-run. Use record_registrations() at session start to log them.
    """
    out: list[ExternalMcpConfig] = []
    for entry in engagement.external_mcp:
        # Re-assert allowlist at runtime as defence-in-depth.
        if entry.name not in ALLOWED_EXTERNAL_MCPS:
            raise PermissionError(
                f"external_mcp {entry.name!r} blocked by allowlist (this should have been "
                "caught by schema validation; do not bypass)"
            )
        out.append(_to_config(entry))
    return out


def record_registrations(configs: list[ExternalMcpConfig], audit: AuditWriter) -> None:
    """Record each registered external MCP to the audit ledger (session start)."""
    for cfg in configs:
        audit.record_external_mcp(
            name=cfg.name,
            status="registered",
            detail=f"tools={cfg.allowed_tools}",
        )


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
