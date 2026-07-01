"""KMS sealer switch (build-next #2).

LedgerWriter takes an injected `Sealer`; the orchestrator defaults to a
`KmsHmacSealer` when `REDTEAM_KMS_KEY_ID` is set and falls back to the
file-key path (local pytest) otherwise. These tests pin the injection
seam and the KMS<->file round-trip without ever making a real AWS call.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from redteam.ledger.chain import LedgerWriter
from redteam.ledger.kms_seal import KmsHmacSealer, build_sealer, write_kms_seal
from redteam.ledger.verify import verify


# ---- build_sealer factory ---------------------------------------------------


def test_build_sealer_returns_kms_when_key_id_set() -> None:
    s = build_sealer(
        {"REDTEAM_KMS_KEY_ID": "arn:aws:kms:us-east-1:1:key/x", "REDTEAM_KMS_REGION": "us-east-1"}
    )
    assert isinstance(s, KmsHmacSealer)
    assert s.key_id == "arn:aws:kms:us-east-1:1:key/x"
    assert s.region == "us-east-1"
    assert s.method == "kms"


def test_build_sealer_returns_none_without_key_id() -> None:
    assert build_sealer({}) is None
    # A region alone (no key id) is not enough to pick KMS.
    assert build_sealer({"REDTEAM_KMS_REGION": "us-east-1"}) is None


def test_build_sealer_region_falls_back_to_aws_env() -> None:
    assert build_sealer({"REDTEAM_KMS_KEY_ID": "arn:x", "AWS_REGION": "eu-west-2"}).region == "eu-west-2"
    assert (
        build_sealer({"REDTEAM_KMS_KEY_ID": "arn:x", "AWS_DEFAULT_REGION": "ap-south-1"}).region
        == "ap-south-1"
    )
    # REDTEAM_KMS_REGION wins over the generic AWS_* fallbacks.
    assert (
        build_sealer(
            {"REDTEAM_KMS_KEY_ID": "arn:x", "REDTEAM_KMS_REGION": "us-east-1", "AWS_REGION": "eu-west-2"}
        ).region
        == "us-east-1"
    )


# ---- LedgerWriter injection -------------------------------------------------


def _writer_with_two_entries(path: Path, **kw) -> LedgerWriter:
    w = LedgerWriter(path, **kw)
    w.append({"kind": "session.start"})
    w.append({"kind": "finding.recorded"})
    return w


def test_ledger_writer_uses_injected_sealer(tmp_path: Path) -> None:
    fake = MagicMock()
    fake.method = "kms"
    w = _writer_with_two_entries(tmp_path / "l.jsonl", sealer=fake)
    target = w.seal()
    fake.write_seal.assert_called_once_with(target, "l.jsonl", w.head_hash, 2)


def test_sealer_takes_precedence_over_hmac_key(tmp_path: Path) -> None:
    fake = MagicMock()
    fake.method = "kms"
    w = _writer_with_two_entries(tmp_path / "l.jsonl", hmac_key=b"k" * 32, sealer=fake)
    w.seal()
    fake.write_seal.assert_called_once()


def test_file_seal_records_method_file_and_verifies(tmp_path: Path) -> None:
    w = _writer_with_two_entries(tmp_path / "l.jsonl", hmac_key=b"k" * 32)
    seal = w.seal()
    doc = json.loads(seal.read_text())
    assert doc["method"] == "file"
    assert verify(tmp_path / "l.jsonl", seal, b"k" * 32) == 0


def test_seal_raises_without_key_or_sealer(tmp_path: Path) -> None:
    w = _writer_with_two_entries(tmp_path / "l.jsonl")
    with pytest.raises(RuntimeError):
        w.seal()


# ---- KMS round-trip through LedgerWriter -----------------------------------


def test_kms_sealer_writes_kms_format_and_verifies(tmp_path: Path, monkeypatch) -> None:
    sealer = KmsHmacSealer(key_id="arn:aws:kms:us-east-1:1:key/x", region="us-east-1")
    monkeypatch.setattr(sealer, "sign", lambda head: "deadbeef")
    w = _writer_with_two_entries(tmp_path / "l.jsonl", sealer=sealer)

    seal = w.seal()
    doc = json.loads(seal.read_text())
    assert doc["method"] == "kms"
    assert doc["mac"] == "deadbeef"
    assert doc["entry_count"] == 2
    assert doc["head_hash"] == w.head_hash
    assert doc["kms_key_arn"] == sealer.key_id

    # The standalone verifier dispatches to the KMS branch (verify → True).
    monkeypatch.setattr(KmsHmacSealer, "verify", lambda self, h, s: True)
    assert verify(tmp_path / "l.jsonl", seal, None) == 0


def test_kms_write_seal_method_matches_free_function(tmp_path: Path, monkeypatch) -> None:
    sealer = KmsHmacSealer(key_id="arn:x", region="us-east-1")
    monkeypatch.setattr(sealer, "sign", lambda head: "cafe")
    a, b = tmp_path / "a.seal", tmp_path / "b.seal"
    sealer.write_seal(a, "l.jsonl", "0" * 64, 3)
    write_kms_seal(b, "l.jsonl", "0" * 64, 3, sealer)
    da, db = json.loads(a.read_text()), json.loads(b.read_text())
    da.pop("sealed_at"), db.pop("sealed_at")  # timestamps differ
    assert da == db


# ---- Orchestrator wiring ----------------------------------------------------


def test_orchestrator_injects_sealer(tmp_path: Path, minimal_engagement_dict) -> None:
    from redteam.engagement import Engagement
    from redteam.orchestrator import Orchestrator

    fake = MagicMock()
    fake.method = "kms"
    eng = Engagement.model_validate(minimal_engagement_dict)
    orch = Orchestrator(
        engagement=eng,
        engagement_path=tmp_path / "e.yaml",
        audit_dir=tmp_path / "audit",
        sealer=fake,
    )
    result = orch.seal(status="complete")
    fake.write_seal.assert_called_once()
    assert result.seal_path is not None
