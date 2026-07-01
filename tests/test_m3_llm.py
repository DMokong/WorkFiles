"""M3 llm.py — the one-shot model seam (text collection is unit-tested; the
actual SDK spawn is never exercised in tests)."""

from __future__ import annotations

from types import SimpleNamespace

from redteam.pipeline import llm


def _text_block(text):
    return SimpleNamespace(text=text)


def test_collect_text_joins_assistant_text_blocks():
    messages = [
        SimpleNamespace(content=[_text_block("hello "), _text_block("world")]),
    ]
    assert llm._collect_text(messages) == "hello world"


def test_collect_text_ignores_non_text_and_contentless_messages():
    messages = [
        SimpleNamespace(subtype="init"),  # no content attr
        SimpleNamespace(content=[SimpleNamespace(tool_use="x"), _text_block("keep")]),
        SimpleNamespace(content="not-a-list"),
    ]
    assert llm._collect_text(messages) == "keep"


def test_ask_is_async_callable():
    import inspect

    assert inspect.iscoroutinefunction(llm.ask)


def test_query_options_grant_no_tools_and_one_turn():
    # The one-shot reasoning turn must get NO tools (source-containment + it stops
    # the model exhausting max_turns=1 with tool_use blocks) and exactly one turn.
    opts = llm._query_options("sys prompt", None)
    assert opts.allowed_tools == []
    assert opts.max_turns == 1
    assert opts.system_prompt == "sys prompt"
