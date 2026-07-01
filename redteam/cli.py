"""Command-line interface for redteam."""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from . import preflight
from .auth import DEFAULT_ALLOWED_SIGNERS, verify_engagement_file
from .engagement import Engagement
from .orchestrator import Orchestrator, load_hmac_key


@click.group()
@click.version_option()
def main() -> None:
    """redteam - modular security testing harness."""


@main.command("doctor")
@click.option(
    "--probe/--no-probe",
    default=False,
    help="Spawn the SDK transport once to confirm the agent loop can launch "
    "(passes without model credentials; only a missing CLI fails).",
)
@click.option(
    "--require-backend",
    is_flag=True,
    help="Treat a missing/unready model backend as a failure (exit non-zero).",
)
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=Path("/audit"),
    help="Audit dir whose writability is checked.",
)
def doctor(probe: bool, require_backend: bool, audit_dir: Path) -> None:
    """Check the container is ready to run an engagement (no token spend)."""
    checks: list[tuple[bool, bool, str, str]] = []  # (ok, required, label, detail)

    # 1. The claude CLI the Agent SDK spawns as its transport.
    cli_path = preflight.find_cli()
    if not cli_path:
        checks.append(
            (False, True, "claude CLI", "not found on PATH (npm i -g @anthropic-ai/claude-code)")
        )
    else:
        try:
            ver = subprocess.run(
                [cli_path, "-v"], capture_output=True, text=True, timeout=10
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as e:
            ver = f"<error: {e}>"
        ok = preflight.cli_version_ok(ver)
        suffix = "" if ok else f" (need >= {'.'.join(map(str, preflight.MIN_CLI_VERSION))})"
        checks.append((ok, True, "claude CLI", f"{ver} at {cli_path}{suffix}"))

    # 2. Model backend (direct key, or Bedrock/Vertex via CLAUDE_CODE_USE_*).
    backend = preflight.detect_backend(os.environ)
    detail = backend.detail + (f" — missing {backend.missing}" if backend.missing else "")
    checks.append((backend.ready, require_backend, f"model backend: {backend.backend}", detail))

    # 3. Writable state dirs under the read-only rootfs (RT-23).
    state_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude"))
    checks.append((preflight.dir_writable(state_dir), True, "SDK state dir", str(state_dir)))
    checks.append((preflight.dir_writable(audit_dir), True, "audit dir", str(audit_dir)))

    # 4. Seal key (informational — file HMAC or KMS; absence is dev-only).
    has_seal = bool(load_hmac_key()) or bool(os.environ.get("REDTEAM_KMS_KEY_ID"))
    checks.append((has_seal, False, "ledger seal key", "present" if has_seal else "absent (dev only)"))

    # 5. Optional live transport probe — proves the SDK can spawn the CLI.
    if probe:
        outcome, pdetail = asyncio.run(_probe_transport())
        # "ok"/"transport_reached" => the CLI spawned (M0 proven). "cli_missing"
        # and "sdk_missing" are distinct hard failures with different fixes.
        checks.append((outcome in ("ok", "transport_reached"), True, f"transport probe: {outcome}", pdetail))

    failures = 0
    for ok, required, label, detail in checks:
        mark = "OK  " if ok else ("FAIL" if required else "WARN")
        if not ok and required:
            failures += 1
        click.echo(f"[{mark}] {label}: {detail}")

    if failures:
        click.echo(f"\ndoctor: {failures} required check(s) failed", err=True)
        sys.exit(1)
    click.echo("\ndoctor: ready")


async def _probe_transport(timeout_s: float = 25.0) -> tuple[str, str]:
    """Spawn the SDK transport once and classify the outcome (no creds needed).

    Connect-only: connecting launches the `claude` CLI subprocess, which is the
    thing M0 must prove. We deliberately send NO query — that would need a model
    backend and (mis)report an auth-error message as a 'response'. A missing
    binary raises CLINotFoundError; anything else means the CLI spawned. The
    subprocess is always torn down (shielded) even if connect times out, so the
    probe can be run repeatedly without orphaning a `claude` process.
    """
    try:
        import anyio
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
    except ImportError as e:
        # The Python package is missing — distinct from a missing CLI binary,
        # with a different fix (`pip install claude-agent-sdk`).
        return "sdk_missing", f"claude_agent_sdk not importable: {e}"
    client = ClaudeSDKClient(options=ClaudeAgentOptions(max_turns=1))
    try:
        with anyio.fail_after(timeout_s):
            await client.connect()
        return "ok", "SDK spawned the claude CLI transport (no model call made)"
    except BaseException as e:  # noqa: BLE001 - classify any failure
        return preflight.classify_probe_error(e), f"{type(e).__name__}: {e}"
    finally:
        with anyio.CancelScope(shield=True), contextlib.suppress(Exception):
            await client.disconnect()


@main.command("validate")
@click.argument("engagement_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate(engagement_file: Path) -> None:
    """Parse + validate an engagement YAML without running anything."""
    try:
        eng = Engagement.from_yaml(engagement_file)
    except Exception as e:  # noqa: BLE001
        click.echo(f"INVALID: {e}", err=True)
        sys.exit(1)
    click.echo(f"OK: {eng.id} ({len(eng.tools)} tool packs, {len(eng.external_mcp)} external MCPs)")


def _report_destination(audit_dir: Path, destination: Path | str) -> Path:
    """Place the SARIF report under ``audit_dir`` using the engagement's filename.

    The ledger and the report are both audit outputs, so they co-locate in
    ``--audit-dir``. Only the basename of ``reporting.destination`` is used, which
    also strips any directory / ``../`` traversal an engagement might carry.
    """
    name = Path(destination).name or "findings.sarif"
    return Path(audit_dir) / name


@main.command("run")
@click.argument("engagement_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=Path("/audit"),
    help="Directory to write the audit ledger and SARIF report into.",
)
@click.option(
    "--assets-root",
    type=click.Path(path_type=Path),
    default=None,
    help="Root the engagement's relative asset paths resolve against "
    "(default: current working directory, i.e. where ./targets was cloned).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Build options and print them, but do not call the SDK or touch disk.",
)
@click.option(
    "--skip-signature",
    is_flag=True,
    help="Local dev only: skip operator signature verification (insecure).",
)
def run(
    engagement_file: Path,
    audit_dir: Path,
    assets_root: Path | None,
    dry_run: bool,
    skip_signature: bool,
) -> None:
    """Execute an engagement."""
    try:
        eng = Engagement.from_yaml(engagement_file)
    except Exception as e:  # noqa: BLE001 - a bad/unsigned YAML must fail cleanly
        click.echo(f"INVALID: {e}", err=True)
        sys.exit(1)

    # Verify the detached operator signature before anything reaches the
    # orchestrator. --dry-run only sanity-checks wiring, so it does not require
    # a signature; a real run fails closed unless --skip-signature is given.
    signature: dict | None = None
    if not dry_run:
        if skip_signature:
            click.echo(
                "WARNING: --skip-signature: running an UNVERIFIED engagement (dev only).",
                err=True,
            )
            signature = {"principal": eng.operator, "ok": False, "detail": "skipped (--skip-signature)"}
        else:
            result = verify_engagement_file(
                engagement_file, eng.operator, allowed_signers=DEFAULT_ALLOWED_SIGNERS
            )
            if not result.ok:
                click.echo(
                    f"REFUSED: operator signature verification failed for "
                    f"{eng.operator}: {result.detail}",
                    err=True,
                )
                sys.exit(3)
            click.echo(f"Signature OK: {eng.operator}")
            signature = {"principal": result.principal, "ok": True, "detail": result.detail}

        # Hard time-bound: refuse to start outside the engagement window.
        if not eng.window.covers(datetime.now(timezone.utc)):
            click.echo(
                f"REFUSED: engagement window is not active "
                f"({eng.window.start.isoformat()}..{eng.window.end.isoformat()})",
                err=True,
            )
            sys.exit(4)

    # Co-locate the SARIF report with the audit ledger under --audit-dir (the
    # report pack and RunResult both read engagement.reporting.destination).
    eng.reporting.destination = _report_destination(audit_dir, eng.reporting.destination)

    try:
        orch = Orchestrator(
            engagement=eng,
            engagement_path=engagement_file.resolve(),
            audit_dir=audit_dir,
            hmac_key=load_hmac_key(),
            assets_root=(assets_root.resolve() if assets_root else Path.cwd()),
        )
        options = orch.build_options()
    except Exception as e:  # noqa: BLE001 - setup must exit cleanly, not traceback
        click.echo(f"SETUP ERROR: {e}", err=True)
        sys.exit(5)
    if dry_run:
        # Strictly read-only: no audit dir, no ledger, no SARIF written.
        click.echo("Engagement: " + eng.id)
        click.echo("Allowed tools: " + ", ".join(options["allowed_tools"]))
        click.echo("MCP servers: " + ", ".join(options["mcp_servers"].keys()))
        click.echo("Subagents: " + ", ".join(options["agents"].keys()))
        return
    asyncio.run(_run_with_sdk(orch, options, signature))


@main.command("triage")
@click.argument("ledger", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--assets-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Root the findings' file locations resolve against, for the "
    "prefilter's file-existence + containment check (read-only).",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for the triaged SARIF / markdown / triage.json "
    "(default: the ledger's parent directory).",
)
@click.option(
    "--verify",
    is_flag=True,
    help="Adversarially verify each finding with the model backend (opt-in; "
    "requires a configured backend).",
)
@click.option(
    "--chain",
    is_flag=True,
    help="Compose kept findings into exploit chains with the model backend "
    "(opt-in; requires a configured backend).",
)
@click.option(
    "--min-confidence",
    type=click.IntRange(0, 10),
    default=7,
    show_default=True,
    help="Confidence gate (0-10) for keeping a TRUE_POSITIVE under --verify.",
)
@click.option("--model", default=None, help="Model id for the verify/chain stages.")
def triage(
    ledger: Path,
    assets_root: Path | None,
    out: Path | None,
    verify: bool,
    chain: bool,
    min_confidence: int,
    model: str | None,
) -> None:
    """Refine a sealed engagement ledger's findings into a triaged report.

    Read-only over the ledger. The deterministic stages (prefilter, dedup,
    enrich, emit) always run and need no model or credentials; --verify and
    --chain are opt-in and require a model backend.
    """
    from .pipeline import emit as pipeline_emit
    from .pipeline import stages
    from .pipeline.load import findings_from_ledger

    # Gate the model stages on a reachable model, mirroring the `run` path:
    # refuse cleanly (no traceback, no artifacts written) only when there is
    # neither an env backend nor a claude CLI to authenticate through.
    if verify or chain:
        ready, detail = preflight.model_stage_ready(os.environ)
        if not ready:
            click.echo(
                "REFUSED: --verify/--chain need a reachable model "
                f"({detail}). Set ANTHROPIC_API_KEY or a "
                "CLAUDE_CODE_USE_BEDROCK/VERTEX backend, log in the claude CLI, "
                "or drop the flags to run the deterministic stages only.",
                err=True,
            )
            sys.exit(2)

    try:
        engagement_id, findings = findings_from_ledger(ledger)
        out_dir = out if out is not None else ledger.parent
        report = stages.run_triage(
            findings,
            engagement_id=engagement_id,
            assets_root=assets_root.resolve() if assets_root else None,
            verify=verify,
            chain=chain,
            min_confidence=min_confidence,
            model=model,
        )
        stem = ledger.stem
        paths = pipeline_emit.emit_report(report, out_dir, stem)
    except Exception as e:  # noqa: BLE001 - triage must exit cleanly, not traceback
        click.echo(f"TRIAGE ERROR: {e}", err=True)
        sys.exit(1)

    m = report.metrics
    summary = (
        f"Triage {report.engagement_id or '(unknown)'}: "
        f"kept={m['kept']} dropped={m['dropped']} chains={len(report.chains)} "
        f"(from {m['input']} findings)"
    )
    if m.get("verified") and m.get("precision") is not None:
        summary += f" precision={m['precision']:.0%}"
    click.echo(summary)
    if report.degraded:
        click.echo(f"  degraded: {report.degraded_reason}")
    click.echo(f"  sarif:    {paths['sarif']}")
    click.echo(f"  report:   {paths['markdown']}")
    click.echo(f"  json:     {paths['triage_json']}")


async def _run_with_sdk(orch: Orchestrator, options: dict, signature: dict | None = None) -> None:
    try:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
    except ImportError as e:
        click.echo(
            f"claude-agent-sdk not installed: {e}\n"
            "  pip install claude-agent-sdk\n"
            "  (or run with --dry-run to validate wiring)",
            err=True,
        )
        sys.exit(2)

    sdk_options = ClaudeAgentOptions(**options)
    orch.start_session(signature=signature)  # writes engagement + signature as entries 0-1
    async with ClaudeSDKClient(options=sdk_options) as client:
        await client.query(orch.engagement.objective)
        async for _msg in client.receive_response():
            pass
    result = orch.seal(status="complete")
    click.echo(f"Engagement {result.engagement_id} sealed: head={result.head_hash[:16]}")
    if result.seal_path:
        click.echo(f"  seal: {result.seal_path}")
    click.echo(f"  sarif: {result.sarif_path}")


if __name__ == "__main__":
    main()
