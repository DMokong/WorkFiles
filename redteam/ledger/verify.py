"""Standalone ledger verifier - no SDK dependency.

Auditors run this against a sealed ledger to confirm the hash chain is
intact and the HMAC seal matches. Only stdlib + the chain module.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

from .chain import replay_chain


def verify(ledger_path: Path, seal_path: Path | None, hmac_key: bytes | None) -> int:
    try:
        head_hash = "0" * 64
        count = 0
        for entry in replay_chain(ledger_path):
            head_hash = entry.payload_hash
            count += 1
    except ValueError as e:
        print(f"FAIL: ledger chain broken: {e}", file=sys.stderr)
        return 2

    print(f"OK: ledger chain intact ({count} entries, head={head_hash[:16]}...)")

    if seal_path is None:
        return 0

    if not seal_path.exists():
        print(f"FAIL: seal file not found: {seal_path}", file=sys.stderr)
        return 3

    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    if seal.get("head_hash") != head_hash:
        print(
            f"FAIL: seal head_hash {seal.get('head_hash')} != ledger head {head_hash}",
            file=sys.stderr,
        )
        return 4
    if seal.get("entry_count") != count:
        print(
            f"FAIL: seal entry_count {seal.get('entry_count')} != observed {count}",
            file=sys.stderr,
        )
        return 5

    # Fail closed: a seal that is present but whose MAC cannot be checked must
    # NOT exit 0. Dispatch on the recorded method (file HMAC vs AWS KMS).
    method = str(seal.get("method", "file"))
    if method in ("file", "hmac"):
        if hmac_key is None:
            print(
                "FAIL: seal present but no --hmac-key-file given; refusing to pass an "
                "unverified HMAC seal (supply the key, or omit the seal argument to "
                "check chain integrity only)",
                file=sys.stderr,
            )
            return 7
        expected = hmac.new(hmac_key, head_hash.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(seal.get("hmac_sha256", ""))):
            print("FAIL: HMAC verification failed - seal forged or wrong key", file=sys.stderr)
            return 6
        print("OK: HMAC seal verified (file key)")
        return 0

    if method == "kms":
        try:
            from .kms_seal import KmsHmacSealer

            sealer = KmsHmacSealer(
                key_id=str(seal.get("kms_key_arn", "")),
                region=str(seal.get("kms_region", "")),
                mac_algorithm=str(seal.get("mac_algorithm", "HMAC_SHA_256")),
            )
            valid = sealer.verify(head_hash, str(seal.get("mac", "")))
        except Exception as e:  # noqa: BLE001 - boto3 missing / no creds / bad ARN
            print(f"FAIL: KMS seal could not be verified: {e}", file=sys.stderr)
            return 8
        if not valid:
            print("FAIL: KMS MAC verification failed - seal forged or wrong key", file=sys.stderr)
            return 6
        print("OK: KMS seal verified (kms:VerifyMac)")
        return 0

    print(f"FAIL: unknown seal method {method!r}", file=sys.stderr)
    return 9


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="redteam-verify")
    p.add_argument("ledger", type=Path, help="path to .jsonl ledger")
    p.add_argument("seal", type=Path, nargs="?", help="optional .seal file")
    p.add_argument(
        "--hmac-key-file",
        type=Path,
        help="file containing the HMAC key as raw bytes",
    )
    args = p.parse_args(argv)
    key: bytes | None = None
    if args.hmac_key_file is not None:
        key = args.hmac_key_file.read_bytes()
    return verify(args.ledger, args.seal, key)


if __name__ == "__main__":
    raise SystemExit(main())
