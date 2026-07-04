"""Tool runtime context - the bundle of state every tool pack receives."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..assets import AssetIndex
from ..engagement import Engagement
from ..hooks.audit_writer import AuditWriter
from ..hooks.scope_guard import ScopeGuard

if TYPE_CHECKING:
    from ..hooks.telemetry import Telemetry


@dataclass
class ToolContext:
    engagement: Engagement
    scope: ScopeGuard
    audit: AuditWriter
    assets: AssetIndex
    audit_dir: Path
    # Optional so tests can build a minimal context; the orchestrator wires the
    # real Telemetry so the report pack can emit finding.recorded spans (RT-22).
    telemetry: "Telemetry | None" = None

    def assert_in_scope(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        decision = self.scope.check(tool_name, tool_input)
        if not decision.allowed:
            raise PermissionError(f"scope deny: {decision.reason}")
