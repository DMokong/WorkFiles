"""Orchestrator - thin wrapper around ClaudeSDKClient.

The orchestrator wires policy (hooks), capability (tool packs), and the
audit ledger together, then hands the engagement objective to the SDK.
Almost no logic lives here - hooks gate, tool packs act, the ledger
records.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .assets import AssetIndex, build_index
from .budget import BudgetLedger
from .engagement import Engagement
from .hooks.audit_writer import AuditWriter
from .hooks.redactor import Redactor
from .hooks.scope_guard import ScopeDecision, ScopeGuard
from .hooks.telemetry import Telemetry
from .ledger.chain import LedgerWriter
from .mcp_external import build_configs as build_external_mcp_configs
from .tools import load_pack
from .tools._context import ToolContext


@dataclass
class RunResult:
    engagement_id: str
    head_hash: str
    entry_count: int
    seal_path: Path | None
    sarif_path: Path
    status: str
    summary: dict[str, Any]


class Orchestrator:
    def __init__(
        self,
        engagement: Engagement,
        engagement_path: Path,
        audit_dir: Path,
        hmac_key: bytes | None = None,
    ):
        self.engagement = engagement
        self.engagement_path = engagement_path
        self.audit_dir = audit_dir
        self.audit_dir.mkdir(parents=True, exist_ok=True)

        ledger_path = audit_dir / f"{engagement.id}.jsonl"
        self.ledger = LedgerWriter(ledger_path, hmac_key=hmac_key)
        self.audit = AuditWriter(self.ledger, redactor=Redactor())
        self.scope = ScopeGuard(engagement)
        self.telemetry = Telemetry(service_name=f"harness:{engagement.id}")
        self.budget = BudgetLedger(spec=engagement.budget)
        self.assets: AssetIndex = build_index(
            engagement.assets, host_root=engagement_path.parent
        )

        self.tool_ctx = ToolContext(
            engagement=engagement,
            scope=self.scope,
            audit=self.audit,
            assets=self.assets,
            audit_dir=self.audit_dir,
        )

    def build_options(self) -> dict[str, Any]:
        """Return the kwargs we'd pass to ClaudeAgentOptions.

        Returned as a plain dict so the orchestrator stays importable
        without the SDK. The CLI converts to the SDK type at call time.
        """
        mcp_servers = self._build_first_party_packs()
        external_configs = build_external_mcp_configs(self.engagement, self.audit)
        for cfg in external_configs:
            mcp_servers[cfg.name] = cfg.sdk_config

        allowed_tools = self._compute_allowed_tools(external_configs)

        return {
            "system_prompt": self._system_prompt(),
            "allowed_tools": allowed_tools,
            "permission_mode": "dontAsk",
            "mcp_servers": mcp_servers,
            "max_turns": self.engagement.budget.max_turns,
            "hooks": self._build_hooks(),
            "agents": self._build_subagents(),
        }

    def _build_first_party_packs(self) -> dict[str, Any]:
        servers: dict[str, Any] = {}
        for name in self.engagement.tools:
            if name in {p for p in ("recon", "web", "cloud", "network", "whitebox", "report")}:
                servers[name] = load_pack(name, self.tool_ctx)
        return servers

    def _compute_allowed_tools(self, external: list[Any]) -> list[str]:
        # Tool names are emitted as "<server>__<tool>" by the SDK.
        # We pre-compute the allowed list rather than relying on hook denial
        # alone - belt and braces.
        allow: list[str] = []
        # First-party tools are everything the loaded packs expose. We can't
        # easily introspect the MCP server objects without running them, so
        # we trust the per-pack allowlist documented in each module and the
        # scope_guard hook.
        for name in self.engagement.tools:
            allow.append(f"{name}__*")
        for cfg in external:
            for t in cfg.allowed_tools:
                allow.append(t if "__" in t else f"{cfg.name}__{t}")
        return allow

    def _system_prompt(self) -> str:
        rules = (
            "You are an authorized security testing agent operating under a strict scope.\n"
            "Hard rules:\n"
            "  - Never call a tool against a host or URL outside scope.targets.\n"
            "  - Never attempt write/delete operations unless the objective explicitly authorizes them.\n"
            "  - Confirm every finding with at least one independent observation before reporting.\n"
            "  - Use the report__write_finding tool to record findings; do not paste them in chat.\n"
            "  - Stop when the objective is met or budget is exhausted; do not improvise scope.\n"
        )
        return f"{rules}\n\nEngagement objective:\n{self.engagement.objective.strip()}\n"

    def _build_hooks(self) -> dict[str, Any]:
        # Hook objects expose async callables the SDK invokes. The SDK API is
        # versioned; we return a dict the CLI can adapt at call time.
        return {
            "PreToolUse": [self._pre_tool_use],
            "PostToolUse": [self._post_tool_use],
            "SessionStart": [self._session_start],
            "SessionEnd": [self._session_end],
        }

    async def _pre_tool_use(self, payload: dict[str, Any]) -> dict[str, Any]:
        tool_name = payload.get("tool_name", "")
        tool_input = payload.get("tool_input", {}) or {}
        tool_use_id = payload.get("tool_use_id", "")
        session_id = payload.get("session_id", "")

        # Budget gate.
        target = _extract_target_for_budget(tool_input)
        breach = self.budget.exceeded(target)
        if breach:
            self.audit.record_pre_tool(
                session_id=session_id,
                tool_use_id=tool_use_id,
                tool_name=tool_name,
                tool_input=tool_input,
                decision="deny",
                reason=f"budget: {breach}",
            )
            self.telemetry.event_tool_denied(tool_name, breach)
            return {"permissionDecision": "deny", "reason": breach}

        decision: ScopeDecision = self.scope.check(tool_name, tool_input)
        self.audit.record_pre_tool(
            session_id=session_id,
            tool_use_id=tool_use_id,
            tool_name=tool_name,
            tool_input=tool_input,
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
        )
        if not decision.allowed:
            self.telemetry.event_tool_denied(tool_name, decision.reason)
            return {"permissionDecision": "deny", "reason": decision.reason}

        if target:
            self.budget.record_tool_call(target)
        return {"permissionDecision": "allow"}

    async def _post_tool_use(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.audit.record_post_tool(
            session_id=payload.get("session_id", ""),
            tool_use_id=payload.get("tool_use_id", ""),
            tool_name=payload.get("tool_name", ""),
            tool_response=payload.get("tool_response"),
            duration_ms=float(payload.get("duration_ms", 0.0)),
            cost_usd=payload.get("cost_usd"),
            error=payload.get("error"),
        )
        if payload.get("cost_usd"):
            self.budget.record_cost(float(payload["cost_usd"]))
        self.budget.record_turn()
        return {}

    async def _session_start(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.audit.record_session_start(self.engagement.model_dump(mode="json"))
        return {}

    async def _session_end(self, payload: dict[str, Any]) -> dict[str, Any]:
        summary = {
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "turns": self.budget.turns,
            "usd": self.budget.usd,
            "tool_calls_per_target": dict(self.budget.tool_calls_per_target),
            "reason": payload.get("reason", "complete"),
        }
        self.audit.record_session_end(summary)
        return {}

    def _build_subagents(self) -> dict[str, str]:
        prompts_dir = Path(__file__).parent / "subagents"
        out: dict[str, str] = {}
        for name in self.engagement.subagents:
            f = prompts_dir / f"{name}.md"
            if f.exists():
                out[name] = f.read_text(encoding="utf-8")
        return out

    def seal(self, status: str = "complete") -> RunResult:
        seal_path: Path | None = None
        try:
            seal_path = self.ledger.seal()
        except RuntimeError:
            pass  # no HMAC key
        return RunResult(
            engagement_id=self.engagement.id,
            head_hash=self.ledger.head_hash,
            entry_count=self.budget.turns,
            seal_path=seal_path,
            sarif_path=Path(self.engagement.reporting.destination),
            status=status,
            summary={
                "turns": self.budget.turns,
                "usd": self.budget.usd,
                "tool_calls_per_target": dict(self.budget.tool_calls_per_target),
            },
        )


def _extract_target_for_budget(tool_input: dict[str, Any]) -> str | None:
    for key in ("url", "target", "host", "endpoint", "address", "cidr"):
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def load_hmac_key() -> bytes | None:
    """Load the seal HMAC key from the conventional secret path."""
    candidates = [Path("/run/secrets/harness_hmac_key"), Path(os.environ.get("HARNESS_HMAC_KEY_FILE", ""))]
    for c in candidates:
        if c and c.is_file():
            return c.read_bytes()
    return None
