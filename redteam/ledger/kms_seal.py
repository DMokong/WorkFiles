"""KMS-backed ledger seal (production path).

Replaces the file-based HMAC seal in `chain.LedgerWriter.seal()` with an
AWS KMS HMAC key (`kms:GenerateMac` / `kms:VerifyMac`). The harness
container assumes a workload role with `kms:GenerateMac` *only* on a
single key ARN; the verifier role gets `kms:VerifyMac` *only*. Key
material never leaves KMS, all usage is CloudTrail-logged.

Wiring (build-next #2, done): `LedgerWriter` accepts an injected `Sealer`.
`build_sealer(env)` returns a `KmsHmacSealer` when `REDTEAM_KMS_KEY_ID`
is set and `None` otherwise, so the orchestrator seals with KMS
in-container and falls back to the file-key path (in chain.py) for local
pytest. Both seal files record `method` ("kms" | "file") so the verifier
and reviewers can tell at a glance. The boto3 calls stay lazy: importing
this module never requires AWS creds; only an actual sign/verify does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Protocol


class Sealer(Protocol):
    method: str

    def sign(self, head_hash: str) -> str: ...

    def verify(self, head_hash: str, signature: str) -> bool: ...

    def write_seal(
        self, seal_path: Path, ledger_name: str, head_hash: str, entry_count: int
    ) -> None: ...


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

    def write_seal(
        self, seal_path: Path, ledger_name: str, head_hash: str, entry_count: int
    ) -> None:
        """Seal a chain head with a KMS MAC.

        The recorded fields (`method`, `kms_key_arn`, `kms_region`,
        `mac_algorithm`, `mac`) are exactly what `verify.py`'s KMS branch
        reads back. `kms:GenerateMac` is called once, here.
        """
        seal_path.write_text(
            json.dumps(
                {
                    "ledger": ledger_name,
                    "head_hash": head_hash,
                    "entry_count": entry_count,
                    "method": self.method,
                    "kms_key_arn": self.key_id,
                    "kms_region": self.region,
                    "mac_algorithm": self.mac_algorithm,
                    "mac": self.sign(head_hash),
                    "sealed_at": datetime.now(timezone.utc).isoformat(),
                },
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )


def build_sealer(env: Mapping[str, str]) -> KmsHmacSealer | None:
    """Pick the production sealer from the environment.

    `REDTEAM_KMS_KEY_ID` set -> `KmsHmacSealer` (KMS is authoritative
    in-container). Absent -> `None`, so `LedgerWriter` falls back to its
    file-key path (local pytest only). Region resolves from
    `REDTEAM_KMS_REGION`, then the standard `AWS_REGION` /
    `AWS_DEFAULT_REGION`; an empty region surfaces as a boto3 error at
    sign time (fail loud), never a silent mis-seal.
    """
    key_id = env.get("REDTEAM_KMS_KEY_ID")
    if not key_id:
        return None
    region = (
        env.get("REDTEAM_KMS_REGION")
        or env.get("AWS_REGION")
        or env.get("AWS_DEFAULT_REGION")
        or ""
    )
    return KmsHmacSealer(key_id=key_id, region=region)


def write_kms_seal(
    seal_path: Path,
    ledger_name: str,
    head_hash: str,
    entry_count: int,
    sealer: KmsHmacSealer,
) -> None:
    """Convenience wrapper: delegates to `sealer.write_seal(...)`."""
    sealer.write_seal(seal_path, ledger_name, head_hash, entry_count)
