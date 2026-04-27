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

    if hmac_key is not None:
        expected = hmac.new(hmac_key, head_hash.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, seal.get("hmac_sha256", "")):
            print("FAIL: HMAC verification failed - seal forged or wrong key", file=sys.stderr)
            return 6
        print("OK: HMAC seal verified")
    else:
        print("WARN: no HMAC key supplied - seal contents matched but signature not checked")

    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harness-verify")
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
