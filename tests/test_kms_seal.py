"""KMS sealer stub.

The KMS path is intentionally a thin wrapper around boto3. These tests
just pin the surface so the next implementation phase can swap in real
KMS calls (or moto) without breaking callers.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from redteam.ledger.kms_seal import KmsHmacSealer, write_kms_seal


def test_kms_sealer_sign_calls_generate_mac(monkeypatch) -> None:
    sealer = KmsHmacSealer(key_id="arn:aws:kms:us-east-1:111111111111:key/abcd", region="us-east-1")
    fake_client = MagicMock()
    fake_client.generate_mac.return_value = {"Mac": b"\x01\x02\x03\x04"}
    monkeypatch.setattr(sealer, "_client", lambda: fake_client)

    sig = sealer.sign("0" * 64)

    assert sig == "01020304"
    fake_client.generate_mac.assert_called_once()
    kwargs = fake_client.generate_mac.call_args.kwargs
    assert kwargs["KeyId"] == sealer.key_id
    assert kwargs["MacAlgorithm"] == "HMAC_SHA_256"


def test_write_kms_seal_records_method(tmp_path: Path, monkeypatch) -> None:
    sealer = KmsHmacSealer(key_id="arn:aws:kms:us-east-1:1:key/x", region="us-east-1")
    monkeypatch.setattr(sealer, "sign", lambda head: "deadbeef")

    seal_path = tmp_path / "ENG.seal"
    write_kms_seal(seal_path, "ENG.jsonl", "0" * 64, 7, sealer)

    seal = json.loads(seal_path.read_text())
    assert seal["method"] == "kms"
    assert seal["mac"] == "deadbeef"
    assert seal["entry_count"] == 7
    assert seal["kms_key_arn"] == sealer.key_id
