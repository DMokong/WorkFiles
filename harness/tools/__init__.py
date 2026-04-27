"""First-party tool packs - in-process stdio MCP servers.

Each pack registers tools via the SDK's `create_sdk_mcp_server`. The
orchestrator picks up the packs listed in the engagement YAML's `tools:`
field and wires them onto the agent.

A pack module must export `build_pack(ctx)` returning an MCP server
object the SDK can register, and `PACK_NAME: str`.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

PACKS = ("recon", "web", "cloud", "network", "whitebox", "report")


def load_pack(name: str, ctx: Any) -> Any:
    if name not in PACKS:
        raise ValueError(f"unknown tool pack: {name!r} (known: {PACKS})")
    mod = import_module(f".{name}", package=__name__)
    return mod.build_pack(ctx)
