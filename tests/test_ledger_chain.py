"""Hash-chained ledger: any post-hoc edit must invalidate downstream entries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.ledger.chain import LedgerWriter, replay_chain


def test_chain_appends_and_replays(tmp_path: Path) -> None:
    w = LedgerWriter(tmp_path / "ledger.jsonl")
    for i in range(5):
        w.append({"event": "tool.invoked", "i": i})
    entries = list(replay_chain(tmp_path / "ledger.jsonl"))
    assert [e.payload["i"] for e in entries] == list(range(5))
    assert entries[-1].payload_hash == w.head_hash


def test_chain_detects_tamper(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    w = LedgerWriter(path)
    for i in range(3):
        w.append({"event": "tool.invoked", "i": i})

    lines = path.read_text().splitlines()
    middle = json.loads(lines[1])
    middle["payload"]["i"] = 999
    lines[1] = json.dumps(middle, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ValueError, match="payload_hash mismatch|prev_hash mismatch"):
        list(replay_chain(path))


def test_seal_requires_key(tmp_path: Path) -> None:
    w = LedgerWriter(tmp_path / "ledger.jsonl")
    w.append({"event": "session.start"})
    with pytest.raises(RuntimeError):
        w.seal()
