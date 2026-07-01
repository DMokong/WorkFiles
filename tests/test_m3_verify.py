"""M3 verify stage — adversarial verdict parse + confidence gate (mocked ask)."""

from __future__ import annotations

import asyncio

from redteam.pipeline import stages
from redteam.pipeline.models import Finding


def _f(title, severity="high"):
    return Finding(title=title, severity=severity, description="d", location="app/x.py:10")


# --- parse_verdict (pure) ----------------------------------------------------


def test_verify_and_chain_prompts_forbid_tool_use():
    # A live-only failure: an "investigate/walk the callers" prompt makes the host
    # CLI's built-in tools tempt the model into tool_use, exhausting max_turns=1
    # and erroring the call. The prompts must instruct reasoning from the provided
    # text only, and must not invite filesystem investigation.
    for prompt in (stages._VERIFY_SYSTEM, stages._CHAIN_SYSTEM):
        assert "NO tools" in prompt
    assert "Walk the callers" not in stages._VERIFY_SYSTEM


def test_parse_verdict_true_positive():
    v = stages.parse_verdict("reasoning...\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable")
    assert v == {"verdict": "TRUE_POSITIVE", "confidence": 9, "reason": "reachable", "cvss_vector": None}


def test_parse_verdict_false_positive():
    v = stages.parse_verdict("VERDICT: FALSE_POSITIVE (confidence: 8/10) — upstream validation")
    assert v["verdict"] == "FALSE_POSITIVE" and v["confidence"] == 8


def test_parse_verdict_captures_cvss_vector():
    reply = (
        "VERDICT: TRUE_POSITIVE (confidence: 8/10) — ok\n"
        "CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    v = stages.parse_verdict(reply)
    assert v["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_parse_verdict_missing_confidence():
    v = stages.parse_verdict("VERDICT: TRUE_POSITIVE — looks real to me")
    assert v["verdict"] == "TRUE_POSITIVE" and v["confidence"] is None


def test_parse_verdict_case_insensitive():
    v = stages.parse_verdict("VERDICT: true_positive (confidence: 9/10) — final")
    assert v["verdict"] == "TRUE_POSITIVE" and v["confidence"] == 9


def test_parse_verdict_bottom_up_among_same_verdict():
    # Two lines with the SAME verdict but different confidence: the last wins.
    reply = "VERDICT: TRUE_POSITIVE (confidence: 2/10) — early\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — final"
    v = stages.parse_verdict(reply)
    assert v["verdict"] == "TRUE_POSITIVE" and v["confidence"] == 9


def test_parse_verdict_none_on_garbage():
    assert stages.parse_verdict("I have opinions but no verdict grammar") is None
    assert stages.parse_verdict("") is None


# --- verify_findings (mocked ask) -------------------------------------------


def _router(mapping, raise_on=None):
    async def ask(system, user, *, model=None):
        if raise_on and raise_on in user:
            raise RuntimeError("transport boom")
        for key, reply in mapping.items():
            if key in user:
                return reply
        return "no verdict"

    return ask


def test_gate_keeps_tp_drops_fp_and_unconfirmed_keeps_unverified():
    findings = [_f("TP high"), _f("TP low"), _f("FP one"), _f("garble")]
    ask = _router(
        {
            "TP high": "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable",
            "TP low": "VERDICT: TRUE_POSITIVE (confidence: 3/10) — maybe",
            "FP one": "VERDICT: FALSE_POSITIVE (confidence: 8/10) — validated upstream",
            "garble": "no verdict grammar at all",
        }
    )
    kept, dropped, degraded = asyncio.run(
        stages.verify_findings(findings, ask=ask, min_confidence=7)
    )
    assert [f.title for f in kept] == ["TP high", "garble"]
    assert degraded is False
    kept_by_title = {f.title: f for f in kept}
    assert kept_by_title["TP high"].verdict == "TRUE_POSITIVE"
    assert kept_by_title["TP high"].verdict_confidence == 9
    # An unparseable verdict is UNVERIFIED and KEPT — never laundered to FP.
    assert kept_by_title["garble"].verdict == "UNVERIFIED"
    dropped_by_title = {d.finding.title: d.reason for d in dropped}
    assert dropped_by_title == {"TP low": "UNCONFIRMED", "FP one": "FALSE_POSITIVE"}


def test_verify_exception_becomes_unverified_and_degrades_when_all_fail():
    findings = [_f("boom")]
    ask = _router({}, raise_on="boom")
    kept, dropped, degraded = asyncio.run(stages.verify_findings(findings, ask=ask))
    assert [f.title for f in kept] == ["boom"]
    assert kept[0].verdict == "UNVERIFIED"
    assert dropped == []
    assert degraded is True  # every verify call failed -> stage degraded


def test_verify_partial_exception_does_not_degrade_whole_stage():
    findings = [_f("boom"), _f("TP ok")]
    ask = _router({"TP ok": "VERDICT: TRUE_POSITIVE (confidence: 10/10) — solid"}, raise_on="boom")
    kept, _dropped, degraded = asyncio.run(stages.verify_findings(findings, ask=ask, min_confidence=7))
    assert {f.title for f in kept} == {"boom", "TP ok"}
    assert degraded is False


def test_verify_cvss_vector_flows_onto_finding():
    findings = [_f("TP vec")]
    ask = _router(
        {
            "TP vec": "VERDICT: TRUE_POSITIVE (confidence: 9/10) — ok\n"
            "CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
    )
    kept, _d, _deg = asyncio.run(stages.verify_findings(findings, ask=ask, min_confidence=7))
    assert kept[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_verify_all_findings_processed_concurrently():
    findings = [_f(f"TP {i}") for i in range(6)]
    ask = _router({f"TP {i}": "VERDICT: TRUE_POSITIVE (confidence: 8/10) — ok" for i in range(6)})
    kept, _d, _deg = asyncio.run(stages.verify_findings(findings, ask=ask, min_confidence=7))
    assert len(kept) == 6
