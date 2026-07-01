"""M3 run_triage with the opt-in verify/chain stages (mocked ask, sync driver)."""

from __future__ import annotations

from pathlib import Path

from redteam.pipeline import stages
from redteam.pipeline.load import findings_from_ledger

FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"


def _load():
    return findings_from_ledger(FIXTURE)


def _verify_router(mapping):
    async def ask(system, user, *, model=None):
        for key, reply in mapping.items():
            if key in user:
                return reply
        return "no verdict"

    return ask


def test_run_triage_verify_applies_gate_and_precision():
    engagement_id, findings = _load()
    ask = _verify_router(
        {
            "SQL injection": "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable",
            "Server-side request forgery": "VERDICT: TRUE_POSITIVE (confidence: 8/10) — reachable",
            "Hardcoded API credential": "VERDICT: FALSE_POSITIVE (confidence: 8/10) — placeholder only",
            "Missing authentication": "VERDICT: TRUE_POSITIVE (confidence: 10/10) — no decorator",
        }
    )
    report = stages.run_triage(
        findings, engagement_id=engagement_id, verify=True, ask=ask, min_confidence=7
    )
    titles = {f.title.split()[0] for f in report.findings}
    assert len(report.findings) == 3  # SQLi, SSRF, missing-auth kept; secret refuted
    assert all(f.verdict == "TRUE_POSITIVE" for f in report.findings)
    assert any(d.reason == "FALSE_POSITIVE" for d in report.dropped)
    assert report.metrics["verified"] is True
    assert report.metrics["precision"] == 0.75  # 3 confirmed of 4 verified
    # Kept findings are still CWE/CVSS enriched (enrich runs after verify).
    assert all(f.cwe and f.cvss_score is not None for f in report.findings)
    assert "SQL" in " ".join(titles) or "Missing" in " ".join(titles)


def test_run_triage_verify_unparseable_is_kept_as_unverified():
    engagement_id, findings = _load()
    # Every verify reply is garbage -> all UNVERIFIED, all kept, none laundered.
    report = stages.run_triage(
        findings, engagement_id=engagement_id, verify=True, ask=_verify_router({})
    )
    assert len(report.findings) == 4
    assert all(f.verdict == "UNVERIFIED" for f in report.findings)
    assert not any(d.reason == "FALSE_POSITIVE" for d in report.dropped)


def test_run_triage_chain_builds_validated_chains():
    engagement_id, findings = _load()

    async def ask(system, user, *, model=None):
        return '[{"title": "leak -> takeover", "steps": [0, 1], "severity": "critical", "narrative": "n"}]'

    report = stages.run_triage(findings, engagement_id=engagement_id, chain=True, ask=ask)
    assert len(report.chains) == 1
    assert report.chains[0].steps == [0, 1]
    assert report.metrics["chains"] == 1


def test_run_triage_chain_degrades_cleanly_on_garbage():
    engagement_id, findings = _load()

    async def ask(system, user, *, model=None):
        return "sorry, no chains"

    report = stages.run_triage(findings, engagement_id=engagement_id, chain=True, ask=ask)
    assert report.chains == []
    assert report.degraded is True and "chain" in report.degraded_reason.lower()
