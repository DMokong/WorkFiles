"""M3 chain stage — robust JSON extraction + step validation (mocked ask)."""

from __future__ import annotations

import asyncio

from redteam.pipeline import stages
from redteam.pipeline.models import Finding


def _f(title, severity="high", line=10):
    return Finding(title=title, severity=severity, description="d", location=f"a.py:{line}")


# --- extract_json (pure) -----------------------------------------------------


def test_extract_json_plain_array():
    assert stages.extract_json('[{"a": 1}]') == [{"a": 1}]


def test_extract_json_object_with_chains():
    assert stages.extract_json('{"chains": []}') == {"chains": []}


def test_extract_json_from_code_fence():
    assert stages.extract_json('```json\n[{"x": 1}]\n```') == [{"x": 1}]


def test_extract_json_ignores_surrounding_prose():
    text = 'Sure, here it is:\n[{"title": "t", "steps": [0, 1]}]\nHope that helps!'
    assert stages.extract_json(text) == [{"title": "t", "steps": [0, 1]}]


def test_extract_json_respects_brackets_inside_strings():
    assert stages.extract_json('{"s": "a]b", "v": [1, 2]}') == {"s": "a]b", "v": [1, 2]}


def test_extract_json_none_on_garbage_or_unbalanced():
    assert stages.extract_json("no json here at all") is None
    # Fully unbalanced (no complete value anywhere) -> None.
    assert stages.extract_json('[{"a": 1') is None
    assert stages.extract_json("") is None


def test_extract_json_recovers_inner_object_from_truncated_wrapper():
    # Best-effort: a truncated array wrapper still yields the complete inner
    # object, so a cut-off chain reply can still be salvaged.
    assert stages.extract_json('[{"a": 1}') == {"a": 1}


# --- build_chains (mocked ask) ----------------------------------------------


def _ask_returning(reply, raise_=False):
    async def ask(system, user, *, model=None):
        if raise_:
            raise RuntimeError("boom")
        return reply

    return ask


def test_build_chains_valid_array():
    findings = [_f("leak"), _f("bypass"), _f("rce")]
    ask = _ask_returning('[{"title": "leak->bypass", "steps": [0, 1], "severity": "high", "narrative": "n"}]')
    chains, degraded = asyncio.run(stages.build_chains(findings, ask=ask))
    assert degraded is False
    assert len(chains) == 1
    assert chains[0].steps == [0, 1] and chains[0].title == "leak->bypass"


def test_build_chains_object_wrapper():
    findings = [_f("a"), _f("b"), _f("c")]
    ask = _ask_returning('{"chains": [{"title": "x", "steps": [0, 2]}]}')
    chains, degraded = asyncio.run(stages.build_chains(findings, ask=ask))
    assert len(chains) == 1 and chains[0].steps == [0, 2] and degraded is False


def test_build_chains_drops_out_of_range_and_short_steps():
    findings = [_f("a"), _f("b"), _f("c")]
    # step 5 doesn't exist -> only [0] in range -> <2 steps -> invalid -> no chains.
    ask = _ask_returning('[{"title": "bad", "steps": [0, 5]}]')
    chains, degraded = asyncio.run(stages.build_chains(findings, ask=ask))
    assert chains == [] and degraded is False


def test_build_chains_dedups_repeated_steps():
    findings = [_f("a"), _f("b"), _f("c")]
    ask = _ask_returning('[{"title": "dup", "steps": [1, 1]}]')  # unique in-range < 2
    chains, _degraded = asyncio.run(stages.build_chains(findings, ask=ask))
    assert chains == []


def test_build_chains_empty_chains_is_not_degraded():
    findings = [_f("a"), _f("b")]
    chains, degraded = asyncio.run(stages.build_chains(findings, ask=_ask_returning('{"chains": []}')))
    assert chains == [] and degraded is False


def test_build_chains_garbage_reply_degrades_to_none():
    findings = [_f("a"), _f("b")]
    chains, degraded = asyncio.run(stages.build_chains(findings, ask=_ask_returning("no json, sorry")))
    assert chains == [] and degraded is True


def test_build_chains_ask_error_degrades_to_none():
    findings = [_f("a"), _f("b")]
    chains, degraded = asyncio.run(stages.build_chains(findings, ask=_ask_returning("", raise_=True)))
    assert chains == [] and degraded is True


def test_build_chains_needs_at_least_two_findings():
    chains, degraded = asyncio.run(stages.build_chains([_f("a")], ask=_ask_returning("[]")))
    assert chains == [] and degraded is False
