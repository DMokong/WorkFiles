"""M3 load.py — tolerant ledger -> Finding loader."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.pipeline.load import findings_from_ledger

FIXTURE = Path(__file__).parent / "fixtures" / "synth-6-findings.jsonl"


def test_loads_synthetic_fixture():
    engagement_id, findings = findings_from_ledger(FIXTURE)
    assert engagement_id == "ENG-SYNTH-01"
    assert len(findings) == 6  # six finding.recorded entries (pre-prefilter)
    assert any("SQL injection" in f.title for f in findings)
    # session.start / signature / session.end lines are not findings.


def test_skips_malformed_lines_without_crashing(tmp_path):
    ledger = tmp_path / "l.jsonl"
    ledger.write_text(
        "\n".join(
            [
                json.dumps({"payload": {"kind": "session.start", "engagement": {"id": "ENG-X"}}}),
                "{ this is not valid json",
                json.dumps({"payload": {"kind": "finding.recorded", "finding": "not-a-dict"}}),
                json.dumps({"payload": {"kind": "finding.recorded", "finding": {"title": "real", "severity": "high", "location": "a.py:1"}}}),
                json.dumps({"payload": {"kind": "tool.pre", "tool": "x"}}),
                "",
            ]
        ),
        encoding="utf-8",
    )
    engagement_id, findings = findings_from_ledger(ledger)
    assert engagement_id == "ENG-X"
    assert len(findings) == 1
    assert findings[0].title == "real"


def test_engagement_id_falls_back_to_finding_when_no_session_start(tmp_path):
    ledger = tmp_path / "l.jsonl"
    ledger.write_text(
        json.dumps(
            {
                "payload": {
                    "kind": "finding.recorded",
                    "finding": {"title": "t", "severity": "low", "engagement_id": "ENG-FB"},
                }
            }
        ),
        encoding="utf-8",
    )
    engagement_id, findings = findings_from_ledger(ledger)
    assert engagement_id == "ENG-FB"
    assert len(findings) == 1


def test_unwrapped_payload_also_supported(tmp_path):
    # Some records may already be the payload (no "payload" envelope).
    ledger = tmp_path / "l.jsonl"
    ledger.write_text(
        json.dumps({"kind": "finding.recorded", "finding": {"title": "bare", "severity": "medium"}}),
        encoding="utf-8",
    )
    _, findings = findings_from_ledger(ledger)
    assert len(findings) == 1 and findings[0].title == "bare"


def test_empty_ledger_returns_empty(tmp_path):
    ledger = tmp_path / "empty.jsonl"
    ledger.write_text("", encoding="utf-8")
    engagement_id, findings = findings_from_ledger(ledger)
    assert engagement_id == ""
    assert findings == []
