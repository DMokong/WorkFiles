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
from typing import TYPE_CHECKING, Any

from .assets import AssetIndex, assert_assets_exist, build_index
from .budget import BudgetLedger
from .engagement import Engagement
from .hooks.audit_writer import AuditWriter
from .hooks.redactor import Redactor
from .hooks.scope_guard import ScopeDecision, ScopeGuard
from .hooks.telemetry import Telemetry, setup_tracing
from .ledger.chain import LedgerWriter
from .mcp_external import build_configs as build_external_mcp_configs
from .mcp_external import record_registrations as record_external_mcp_registrations
from .tools import load_pack
from .tools._context import ToolContext
from .tools._sdk_shim import AgentDefinition, HookMatcher

if TYPE_CHECKING:
    from .ledger.kms_seal import Sealer


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
        sealer: "Sealer | None" = None,
        assets_root: Path | None = None,
    ):
        self.engagement = engagement
        self.engagement_path = engagement_path
        self.audit_dir = audit_dir
        # Asset paths in the YAML are resolved against `assets_root` (the
        # directory the operator runs `redteam` from, i.e. where ./targets was
        # cloned), NOT the engagement file's parent. Defaults to CWD.
        self.assets_root = (assets_root or Path.cwd()).resolve()
        self._session_started = False

        # Construction must be side-effect-free so --dry-run touches no disk.
        # The audit dir is created in start_session(); LedgerWriter is lazy.
        ledger_path = audit_dir / f"{engagement.id}.jsonl"
        # `sealer` (KMS in-container) is authoritative over `hmac_key`; when it
        # is None the LedgerWriter uses the file-key path for local pytest.
        self.ledger = LedgerWriter(ledger_path, hmac_key=hmac_key, sealer=sealer)
        self.audit = AuditWriter(self.ledger, redactor=Redactor())
        self.scope = ScopeGuard(engagement)
        self.telemetry = Telemetry(service_name=f"redteam:{engagement.id}")
        self.budget = BudgetLedger(spec=engagement.budget)
        # Lenient at construction so --dry-run tolerates un-cloned assets;
        # start_session() validates existence for a real run.
        self.assets: AssetIndex = build_index(
            engagement.assets, host_root=self.assets_root, require_exists=False
        )

        self.tool_ctx = ToolContext(
            engagement=engagement,
            scope=self.scope,
            audit=self.audit,
            assets=self.assets,
            audit_dir=self.audit_dir,
            telemetry=self.telemetry,
        )

    def build_options(self) -> dict[str, Any]:
        """Return the kwargs the CLI passes to ClaudeAgentOptions(**options).

        Pure: no filesystem or ledger side effects, so it is safe to call under
        --dry-run. Session-start audit records happen in start_session().
        """
        mcp_servers = self._build_first_party_packs()
        external_configs = build_external_mcp_configs(self.engagement)
        for cfg in external_configs:
            mcp_servers[cfg.name] = cfg.sdk_config
        self._external_configs = external_configs

        return {
            "system_prompt": self._system_prompt(),
            "allowed_tools": self._compute_allowed_tools(external_configs),
            "permission_mode": "dontAsk",  # hooks decide; never prompt a human
            "mcp_servers": mcp_servers,
            "max_turns": self.engagement.budget.max_turns,
            "max_budget_usd": self.engagement.budget.max_usd,
            "hooks": self._build_hooks(),
            "agents": self._build_subagents(),
        }

    _FIRST_PARTY_PACKS = ("recon", "web", "cloud", "network", "whitebox", "report")

    def _build_first_party_packs(self) -> dict[str, Any]:
        servers: dict[str, Any] = {}
        for name in self.engagement.tools:
            if name in self._FIRST_PARTY_PACKS:
                servers[name] = load_pack(name, self.tool_ctx)
        return servers

    def _compute_allowed_tools(self, external: list[Any]) -> list[str]:
        # The SDK exposes in-process MCP tools as ``mcp__<server>__<tool>``.
        # Granting the whole server (``mcp__<server>``) allows every tool the
        # loaded pack exposes; the PreToolUse scope-guard hook is the
        # authoritative gate, this list is belt-and-braces. External MCPs are
        # restricted to their explicit allowed_tools subset.
        allow: list[str] = [
            f"mcp__{name}"
            for name in self.engagement.tools
            if name in self._FIRST_PARTY_PACKS
        ]
        for cfg in external:
            for t in cfg.allowed_tools:
                allow.append(t if t.startswith("mcp__") else f"mcp__{cfg.name}__{t}")
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
        # SessionStart/SessionEnd are NOT Agent SDK hook events; we run those
        # in start_session()/seal() around the query loop. Only PreToolUse and
        # PostToolUse are registered, each wrapped in a HookMatcher per the SDK
        # API. The callbacks take (input_data, tool_use_id, context).
        return {
            "PreToolUse": [HookMatcher(hooks=[self._pre_tool_use])],
            "PostToolUse": [HookMatcher(hooks=[self._post_tool_use])],
        }

    @staticmethod
    def _deny(reason: str) -> dict[str, Any]:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    def within_window(self) -> bool:
        """Is the engagement's hard time-bound currently active?"""
        return self.engagement.window.covers(datetime.now(timezone.utc))

    def _window_reason(self) -> str:
        w = self.engagement.window
        return (
            f"outside engagement window "
            f"{w.start.isoformat()}..{w.end.isoformat()}"
        )

    async def _pre_tool_use(
        self, input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any]:
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {}) or {}
        tool_use_id = tool_use_id or input_data.get("tool_use_id", "")
        session_id = input_data.get("session_id", "")
        target = _extract_target_for_budget(tool_input)

        # One span per pre-tool-use decision; the tool.invoked / tool.denied leaf
        # spans emitted below become its children (RT-22).
        with self.telemetry.tool_span(tool_name, {"target": target or ""}):
            try:
                # Time-window gate: the engagement is only authorized inside its
                # window, including a run that started valid but crossed window.end.
                if not self.within_window():
                    reason = self._window_reason()
                    self.audit.record_pre_tool(
                        session_id=session_id,
                        tool_use_id=tool_use_id,
                        tool_name=tool_name,
                        tool_input=tool_input,
                        decision="deny",
                        reason=reason,
                    )
                    self.telemetry.event_tool_denied(tool_name, reason)
                    return self._deny(reason)

                # Budget gate.
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
                    return self._deny(breach)

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
                    return self._deny(decision.reason)

                if target:
                    self.budget.record_tool_call(target)
                # No opinion -> proceeds under permission_mode="dontAsk" (allowed).
                self.telemetry.event_tool_invoked(tool_name, target)
                return {}
            except Exception as e:  # noqa: BLE001 - the gate must fail closed
                self.telemetry.event_tool_denied(tool_name, f"internal error: {e}")
                return self._deny(f"scope guard internal error: {e}")

    async def _post_tool_use(
        self, input_data: dict[str, Any], tool_use_id: str | None, context: Any
    ) -> dict[str, Any]:
        # PostToolUse input carries no cost/duration; model spend is capped
        # natively via max_budget_usd. We record what is available.
        self.audit.record_post_tool(
            session_id=input_data.get("session_id", ""),
            tool_use_id=tool_use_id or input_data.get("tool_use_id", ""),
            tool_name=input_data.get("tool_name", ""),
            tool_response=input_data.get("tool_response"),
            duration_ms=0.0,
            cost_usd=None,
            error=None,
        )
        self.budget.record_turn()
        return {}

    def start_session(self, signature: dict[str, Any] | None = None) -> None:
        """Begin a real engagement: create the audit dir, write entry 0.

        Called by the CLI only for an actual run - never for --dry-run, which
        must leave the filesystem untouched. `signature` is the operator
        signature-verification outcome, recorded into the ledger.
        """
        if self._session_started:
            return
        assert_assets_exist(self.assets)  # fail early if targets weren't cloned
        # Install a real TracerProvider so the harness's own tool.invoked /
        # tool.denied / finding.recorded spans reach the collector (RT-22).
        # No-ops cleanly when there is no OTLP endpoint (local dev).
        setup_tracing(
            f"redteam:{self.engagement.id}",
            endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"),
        )
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.audit.record_session_start(self.engagement.model_dump(mode="json"))
        if signature is not None:
            self.audit.record_signature(
                principal=signature.get("principal", self.engagement.operator),
                ok=bool(signature.get("ok")),
                detail=str(signature.get("detail", "")),
            )
        record_external_mcp_registrations(
            getattr(self, "_external_configs", []), self.audit
        )
        self._session_started = True

    def _build_subagents(self) -> dict[str, Any]:
        prompts_dir = Path(__file__).parent / "subagents"
        out: dict[str, Any] = {}
        for name in self.engagement.subagents:
            f = prompts_dir / f"{name}.md"
            if not f.exists():
                continue
            meta, body = _parse_frontmatter(f.read_text(encoding="utf-8"))
            out[name] = AgentDefinition(
                description=meta.get("description", f"{name} subagent"),
                prompt=body,
                # Map the frontmatter tool names to the SDK's mcp__ form so the
                # per-subagent tool subset is actually enforced (least privilege).
                tools=_map_subagent_tools(meta),
            )
        return out

    def seal(self, status: str = "complete") -> RunResult:
        if self._session_started:
            self.audit.record_session_end(
                {
                    "ended_at": datetime.now(timezone.utc).isoformat(),
                    "turns": self.budget.turns,
                    "usd": self.budget.usd,
                    "tool_calls_per_target": dict(self.budget.tool_calls_per_target),
                    "reason": status,
                }
            )
        seal_path: Path | None = None
        try:
            seal_path = self.ledger.seal()
        except RuntimeError:
            pass  # neither a KMS sealer nor a file HMAC key present (dev only)
        return RunResult(
            engagement_id=self.engagement.id,
            head_hash=self.ledger.head_hash,
            entry_count=self.ledger.entry_count,
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


def _map_subagent_tools(meta: dict[str, Any]) -> list[str] | None:
    """Map a subagent's frontmatter ``tools:`` to SDK tool names.

    Least-privilege semantics, distinguishing the three cases carefully:
      - absent / null  -> None  (SDK default: inherit the parent's tools)
      - a list         -> mapped names; an *empty* list stays empty (ZERO tools,
                          NOT None - so ``tools: []`` restricts rather than grants)
      - anything else  -> [] (fail closed: a malformed restriction grants nothing)
    """
    raw = meta.get("tools")
    if raw is None:
        return None
    if isinstance(raw, list):
        return [_sdk_tool_name(str(t)) for t in raw]
    return []


def _sdk_tool_name(name: str) -> str:
    """Map a registered tool name to the SDK's exposed ``mcp__<server>__...``.

    Subagent frontmatter lists tools as ``<pack>__<tool>`` (first-party) or an
    already-prefixed external name; the SDK exposes in-process MCP tools as
    ``mcp__<server>__<tool>`` where the @tool name embeds the pack prefix.
    """
    if name.startswith("mcp__"):
        return name
    pack = name.split("__", 1)[0]
    return f"mcp__{pack}__{name}"


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split a subagent markdown file into (frontmatter dict, prompt body).

    The body excludes the YAML frontmatter so it is not fed to the model as
    literal text. Falls back to ({}, whole-text) when there is no frontmatter.
    """
    import yaml

    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except yaml.YAMLError:
                meta = {}
            if isinstance(meta, dict):
                return meta, parts[2].lstrip("\n")
    return {}, text


def load_hmac_key() -> bytes | None:
    """Load the seal HMAC key from the conventional secret path."""
    candidates = [Path("/run/secrets/redteam_hmac_key"), Path(os.environ.get("REDTEAM_HMAC_KEY_FILE", ""))]
    for c in candidates:
        if c and c.is_file():
            return c.read_bytes()
    return None
