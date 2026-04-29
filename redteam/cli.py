"""Command-line interface for redteam."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click

from .engagement import Engagement
from .orchestrator import Orchestrator, load_hmac_key


@click.group()
@click.version_option()
def main() -> None:
    """redteam - modular security testing harness."""


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


@main.command("run")
@click.argument("engagement_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=Path("/audit"),
    help="Directory to write the audit ledger and SARIF report into.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Build options and print them, but do not call the SDK.",
)
def run(engagement_file: Path, audit_dir: Path, dry_run: bool) -> None:
    """Execute an engagement."""
    eng = Engagement.from_yaml(engagement_file)
    orch = Orchestrator(
        engagement=eng,
        engagement_path=engagement_file.resolve(),
        audit_dir=audit_dir,
        hmac_key=load_hmac_key(),
    )
    options = orch.build_options()
    if dry_run:
        click.echo("Engagement: " + eng.id)
        click.echo("Allowed tools: " + ", ".join(options["allowed_tools"]))
        click.echo("MCP servers: " + ", ".join(options["mcp_servers"].keys()))
        click.echo("Subagents: " + ", ".join(options["agents"].keys()))
        return
    asyncio.run(_run_with_sdk(orch, options))


async def _run_with_sdk(orch: Orchestrator, options: dict) -> None:
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
