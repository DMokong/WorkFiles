"""Audit writer - PreToolUse + PostToolUse hooks that append to the ledger.

The ledger is the source of truth for "what did the agent do, with what
input, and what was decided". PreToolUse records the call before
execution; PostToolUse records the (hashed, redacted) result.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..ledger.chain import LedgerWriter
from .redactor import Redactor


class AuditWriter:
    def __init__(self, writer: LedgerWriter, redactor: Redactor | None = None):
        self.writer = writer
        self.redactor = redactor or Redactor()

    def record_session_start(self, engagement_dict: dict[str, Any]) -> None:
        self.writer.append(
            {
                "kind": "session.start",
                "engagement": engagement_dict,
            }
        )

    def record_session_end(self, summary: dict[str, Any]) -> None:
        self.writer.append({"kind": "session.end", "summary": summary})

    def record_pre_tool(
        self,
        *,
        session_id: str,
        tool_use_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        decision: str,
        reason: str,
        mcp_server: str | None = None,
    ) -> None:
        self.writer.append(
            {
                "kind": "tool.pre",
                "session_id": session_id,
                "tool_use_id": tool_use_id,
                "tool": tool_name,
                "mcp_server": mcp_server,
                "input": self.redactor.scrub(tool_input),
                "decision": decision,
                "reason": reason,
            }
        )

    def record_post_tool(
        self,
        *,
        session_id: str,
        tool_use_id: str,
        tool_name: str,
        tool_response: Any,
        duration_ms: float,
        cost_usd: float | None = None,
        error: str | None = None,
    ) -> None:
        body_str = _stringify(tool_response)
        self.writer.append(
            {
                "kind": "tool.post",
                "session_id": session_id,
                "tool_use_id": tool_use_id,
                "tool": tool_name,
                "output_hash": hashlib.sha256(body_str.encode("utf-8")).hexdigest(),
                "output_redacted": self.redactor.scrub(tool_response),
                "duration_ms": duration_ms,
                "cost_usd": cost_usd,
                "error": error,
            }
        )

    def record_finding(self, finding: dict[str, Any]) -> None:
        self.writer.append({"kind": "finding.recorded", "finding": self.redactor.scrub(finding)})

    def record_external_mcp(
        self,
        *,
        name: str,
        status: str,
        detail: str,
    ) -> None:
        self.writer.append(
            {
                "kind": f"mcp.external.{status}",
                "name": name,
                "detail": detail,
            }
        )


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    import json

    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)
