"""One-shot model seam for the opt-in verify/chain stages.

``ask`` runs a single, tool-free reasoning turn over the Agent SDK's ``query()``
one-shot API. ``query()`` spawns the ``claude`` CLI, so it reuses the
engagement's auth (host Claude Code login today, Bedrock/Vertex later) — the same
transport the ``run`` command uses. Kept deliberately thin and injectable: the
stages take ``ask`` as a parameter so tests never spawn a model.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any


def _collect_text(messages: Iterable[Any]) -> str:
    """Concatenate the text of every assistant ``TextBlock`` in a message stream.

    Duck-typed on purpose (``.content`` -> blocks with ``.text``) so it is
    testable without importing SDK message classes and tolerant of the many
    non-text message kinds the stream carries (system/result/tool blocks).
    """
    parts: list[str] = []
    for msg in messages:
        content = getattr(msg, "content", None)
        if not isinstance(content, (list, tuple)):
            continue
        for block in content:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _query_options(system: str, model: str | None):
    """Build the one-shot ``query()`` options.

    ``allowed_tools=[]`` grants the reasoning turn NO tools. This is load-bearing
    two ways: (1) it keeps the model inside the pipeline's source-containment — a
    verify turn reasons only from the excerpt ``_source_window`` feeds it and
    cannot read files outside the asset scope via the host CLI's built-in
    Read/Grep/Bash; and (2) it stops the model from emitting tool_use blocks that
    would exhaust ``max_turns=1`` and error the call.
    """
    from claude_agent_sdk import ClaudeAgentOptions

    return ClaudeAgentOptions(
        system_prompt=system, max_turns=1, model=model, allowed_tools=[]
    )


async def ask(
    system: str, user: str, *, model: str | None = None, timeout_s: float = 120.0
) -> str:
    """Run one tool-free reasoning turn and return the assistant's text.

    Raises a clear ``RuntimeError`` when the SDK/CLI transport cannot be reached
    (the CLI gates on ``detect_backend`` first, and each verify call is wrapped
    so a transport failure degrades that finding to UNVERIFIED rather than
    crashing the pipeline).
    """
    try:
        from claude_agent_sdk import query
    except ImportError as e:  # pragma: no cover - SDK is present in this repo
        raise RuntimeError(f"claude-agent-sdk not installed: {e}") from e

    options = _query_options(system, model)

    async def _run() -> list[Any]:
        collected: list[Any] = []
        async for msg in query(prompt=user, options=options):
            collected.append(msg)
        return collected

    try:
        messages = await asyncio.wait_for(_run(), timeout=timeout_s)
    except asyncio.TimeoutError as e:
        raise RuntimeError(f"model call timed out after {timeout_s}s") from e
    except Exception as e:  # noqa: BLE001 - surface any transport failure uniformly
        raise RuntimeError(f"model call failed: {e}") from e
    return _collect_text(messages)
