"""KMS-backed ledger seal (production path).

Replaces the file-based HMAC seal in `chain.LedgerWriter.seal()` with an
AWS KMS HMAC key (`kms:GenerateMac` / `kms:VerifyMac`). The harness
container assumes a workload role with `kms:GenerateMac` *only* on a
single key ARN; the verifier role gets `kms:VerifyMac` *only*. Key
material never leaves KMS, all usage is CloudTrail-logged.

Blueprint stub: the boto3 calls are sketched but not wired into the
orchestrator yet. The local-dev HMAC-file path in chain.py remains as a
fallback. Next iteration should:
  - inject a `Sealer` protocol into LedgerWriter (KMS or file)
  - default to KMS in container, file in local pytest
  - record `seal.method = "kms" | "file"` on the seal so reviewers can
    tell at a glance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


class Sealer(Protocol):
    method: str

    def sign(self, head_hash: str) -> str: ...

    def verify(self, head_hash: str, signature: str) -> bool: ...


@dataclass
class KmsHmacSealer:
    """Calls KMS GenerateMac / VerifyMac. Container needs the IAM role.

    Required env / config:
      REDTEAM_KMS_KEY_ID    full ARN of an HMAC_256 KMS key
      REDTEAM_KMS_REGION    e.g. us-east-1
    """

    key_id: str
    region: str
    method: str = "kms"
    mac_algorithm: str = "HMAC_SHA_256"

    def _client(self):  # pragma: no cover - boto3 imported lazily
        import boto3

        return boto3.client("kms", region_name=self.region)

    def sign(self, head_hash: str) -> str:
        client = self._client()
        resp = client.generate_mac(
            Message=head_hash.encode("ascii"),
            KeyId=self.key_id,
            MacAlgorithm=self.mac_algorithm,
        )
        return resp["Mac"].hex()

    def verify(self, head_hash: str, signature: str) -> bool:
        client = self._client()
        resp = client.verify_mac(
            Message=head_hash.encode("ascii"),
            KeyId=self.key_id,
            MacAlgorithm=self.mac_algorithm,
            Mac=bytes.fromhex(signature),
        )
        return bool(resp.get("MacValid"))


def write_kms_seal(
    seal_path: Path,
    ledger_name: str,
    head_hash: str,
    entry_count: int,
    sealer: KmsHmacSealer,
) -> None:
    """Convenience: produce a seal file using a KMS HMAC."""
    seal_path.write_text(
        json.dumps(
            {
                "ledger": ledger_name,
                "head_hash": head_hash,
                "entry_count": entry_count,
                "method": sealer.method,
                "kms_key_arn": sealer.key_id,
                "kms_region": sealer.region,
                "mac_algorithm": sealer.mac_algorithm,
                "mac": sealer.sign(head_hash),
                "sealed_at": datetime.now(timezone.utc).isoformat(),
            },
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )
