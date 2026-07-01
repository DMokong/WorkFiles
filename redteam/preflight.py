"""Readiness checks for `redteam doctor` — no token spend, no model calls.

The Claude Agent SDK runs the agent loop by spawning the `claude` CLI as a
subprocess transport. A real engagement therefore needs three things this
module can verify cheaply: the CLI is installed and recent enough, a model
backend is configured (direct Anthropic key, or Amazon Bedrock / Google Vertex
via the `CLAUDE_CODE_USE_*` flags — in which case `ANTHROPIC_API_KEY` is
ignored), and the writable state dirs the run needs exist. The live
spawn-to-auth probe lives in the CLI; its error *classification* is here so it
can be unit-tested without a model.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

# Keep in sync with the Agent SDK's MINIMUM_CLAUDE_CODE_VERSION (2.0.0 as of
# claude_agent_sdk 0.2.98). The image pins @anthropic-ai/claude-code well above
# this; the check guards against a drift that would silently degrade features.
MIN_CLI_VERSION = (2, 0, 0)

_TRUTHY = {"1", "true", "yes", "on"}


@dataclass
class BackendInfo:
    backend: str  # "anthropic_api_key" | "bedrock" | "vertex" | "none"
    ready: bool
    detail: str = ""
    missing: list[str] = field(default_factory=list)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUTHY


def detect_backend(env: Mapping[str, str]) -> BackendInfo:
    """Determine which model backend the spawned `claude` CLI will use.

    Precedence matches the CLI: a `CLAUDE_CODE_USE_*` cloud flag wins, and
    `ANTHROPIC_API_KEY` is ignored when one is set.
    """
    if _truthy(env.get("CLAUDE_CODE_USE_BEDROCK")) or _truthy(env.get("CLAUDE_CODE_USE_MANTLE")):
        # Credentials resolve from the AWS chain (env keys / profile / role) at
        # runtime; presence can't be confirmed here without an STS call.
        return BackendInfo(
            backend="bedrock",
            ready=True,
            detail="AWS credential chain (region from AWS_REGION, default us-east-1)",
        )
    if _truthy(env.get("CLAUDE_CODE_USE_VERTEX")):
        missing = [k for k in ("ANTHROPIC_VERTEX_PROJECT_ID",) if not env.get(k)]
        return BackendInfo(
            backend="vertex",
            ready=not missing,
            detail="Google ADC (project from ANTHROPIC_VERTEX_PROJECT_ID, region from CLOUD_ML_REGION)",
            missing=missing,
        )
    if env.get("ANTHROPIC_API_KEY"):
        return BackendInfo(backend="anthropic_api_key", ready=True, detail="direct Anthropic API")
    return BackendInfo(
        backend="none",
        ready=False,
        detail="no model backend configured",
        missing=["ANTHROPIC_API_KEY or CLAUDE_CODE_USE_BEDROCK/CLAUDE_CODE_USE_VERTEX"],
    )


def model_stage_ready(env: Mapping[str, str]) -> tuple[bool, str]:
    """Whether the opt-in triage model stages (--verify/--chain) can reach a model.

    Ready when an env backend is configured (direct key / Bedrock / Vertex) OR a
    `claude` CLI is present to authenticate through (e.g. a Claude Code login /
    session on a dev host, which ``detect_backend`` cannot see). Mirrors the
    `run` command, which lets the spawned CLI handle auth; a present-but-not-
    logged-in CLI then fails per-call at runtime and each verify degrades to
    UNVERIFIED rather than being refused up front. Refuse only when there is
    neither."""
    backend = detect_backend(env)
    if backend.ready:
        return True, f"model backend: {backend.backend}"
    cli = find_cli()
    if cli:
        return True, f"claude CLI at {cli} (login/session auth)"
    return False, "no model backend and no claude CLI"


def cli_version_ok(version_output: str) -> bool:
    """True if a `claude -v` string is at or above the SDK's minimum version.

    Tolerates an optional ``v`` prefix and a two-part ``MAJOR.MINOR`` (patch
    defaults to 0) so a cosmetic version shape never fails an adequate CLI.
    """
    m = re.match(r"\s*v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", version_output or "")
    if not m:
        return False
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return (major, minor, patch) >= MIN_CLI_VERSION


def _default_cli_fallbacks() -> list[Path]:
    """Non-PATH locations the Agent SDK's transport also searches for `claude`."""
    home = Path.home()
    return [
        home / ".npm-global/bin/claude",
        Path("/usr/local/bin/claude"),
        home / ".local/bin/claude",
        home / "node_modules/.bin/claude",
        home / ".yarn/bin/claude",
        home / ".claude/local/claude",
    ]


def find_cli(fallbacks: list[Path] | None = None) -> str | None:
    """Path to the `claude` binary, or None.

    Mirrors the SDK transport's resolution: PATH first (``shutil.which``), then
    the same fallback install locations the SDK checks — so doctor's verdict
    matches what a real run will actually spawn.
    """
    if cli := shutil.which("claude"):
        return cli
    for cand in fallbacks if fallbacks is not None else _default_cli_fallbacks():
        if Path(cand).is_file():
            return str(cand)
    return None


def classify_probe_error(exc: BaseException | None) -> str:
    """Classify the outcome of attempting to spawn the SDK transport.

    - None                -> "ok"                 (connected, no error)
    - CLINotFoundError    -> "cli_missing"        (binary absent — hard failure)
    - any other exception -> "transport_reached"  (CLI spawned; only creds/auth
                                                   are missing — wiring is good)
    """
    if exc is None:
        return "ok"
    try:
        from claude_agent_sdk import CLINotFoundError
    except ImportError:  # pragma: no cover - SDK always present in this repo
        CLINotFoundError = ()  # type: ignore[assignment]
    if isinstance(exc, CLINotFoundError):
        return "cli_missing"
    return "transport_reached"


def dir_writable(path: Path) -> bool:
    """True if a throwaway file can be created and removed under `path`."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".doctor-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False
