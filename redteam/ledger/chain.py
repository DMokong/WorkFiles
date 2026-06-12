"""Hash-chained append-only audit ledger.

Each entry: {seq, ts, prev_hash, payload, payload_hash}. Mutating any
entry invalidates every downstream entry's prev_hash. SessionEnd writes
an HMAC over the chain head into a sibling .seal file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS_PREV_HASH = "0" * 64


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    ts: str
    prev_hash: str
    payload: dict[str, Any]
    payload_hash: str

    def to_json_line(self) -> str:
        return (
            json.dumps(
                {
                    "seq": self.seq,
                    "ts": self.ts,
                    "prev_hash": self.prev_hash,
                    "payload": self.payload,
                    "payload_hash": self.payload_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LedgerEntry":
        try:
            return cls(
                seq=int(d["seq"]),
                ts=str(d["ts"]),
                prev_hash=str(d["prev_hash"]),
                payload=d["payload"],
                payload_hash=str(d["payload_hash"]),
            )
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"malformed ledger entry: {e}") from e


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_payload_hash(payload: dict[str, Any], prev_hash: str, seq: int) -> str:
    """Hash binds payload to its position in the chain."""
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(seq.to_bytes(8, "big"))
    h.update(_canonical(payload))
    return h.hexdigest()


class LedgerWriter:
    """Append-only writer. Not thread-safe; one process owns one ledger."""

    def __init__(self, path: Path | str, hmac_key: bytes | None = None):
        # Construction is side-effect-free: the parent dir and file are created
        # lazily on the first append()/seal(), so a --dry-run that constructs a
        # LedgerWriter never touches the filesystem.
        self.path = Path(path)
        self._hmac_key = hmac_key
        self._seq = 0
        self._head_hash = GENESIS_PREV_HASH
        if self.path.exists() and self.path.stat().st_size > 0:
            self._resume()

    @property
    def entry_count(self) -> int:
        """Number of entries appended/observed so far (the next seq)."""
        return self._seq

    def _resume(self) -> None:
        last: LedgerEntry | None = None
        for entry in replay_chain(self.path):
            last = entry
        if last is not None:
            self._seq = last.seq + 1
            self._head_hash = last.payload_hash

    def append(self, payload: dict[str, Any]) -> LedgerEntry:
        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        entry = LedgerEntry(
            seq=self._seq,
            ts=ts,
            prev_hash=self._head_hash,
            payload=payload,
            payload_hash=compute_payload_hash(payload, self._head_hash, self._seq),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json_line())
            f.flush()
            os.fsync(f.fileno())
        self._seq += 1
        self._head_hash = entry.payload_hash
        return entry

    @property
    def head_hash(self) -> str:
        return self._head_hash

    def seal(self, seal_path: Path | str | None = None) -> Path:
        if self._hmac_key is None:
            raise RuntimeError("seal() requires an HMAC key")
        target = Path(seal_path) if seal_path else self.path.with_suffix(".seal")
        target.parent.mkdir(parents=True, exist_ok=True)
        sig = hmac.new(self._hmac_key, self._head_hash.encode("ascii"), hashlib.sha256)
        target.write_text(
            json.dumps(
                {
                    "ledger": str(self.path.name),
                    "head_hash": self._head_hash,
                    "entry_count": self._seq,
                    "hmac_sha256": sig.hexdigest(),
                    "sealed_at": datetime.now(timezone.utc).isoformat(),
                },
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )
        return target


def replay_chain(path: Path | str) -> Iterator[LedgerEntry]:
    """Yield entries in order, raising ValueError on the first corruption."""
    expected_prev = GENESIS_PREV_HASH
    expected_seq = 0
    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"line {line_no}: invalid JSON: {e}") from e
            entry = LedgerEntry.from_dict(raw)
            if entry.seq != expected_seq:
                raise ValueError(
                    f"line {line_no}: expected seq {expected_seq}, got {entry.seq}"
                )
            if entry.prev_hash != expected_prev:
                raise ValueError(
                    f"line {line_no}: prev_hash mismatch (chain broken at seq {entry.seq})"
                )
            recomputed = compute_payload_hash(entry.payload, entry.prev_hash, entry.seq)
            if recomputed != entry.payload_hash:
                raise ValueError(
                    f"line {line_no}: payload_hash mismatch (entry tampered, seq {entry.seq})"
                )
            yield entry
            expected_prev = entry.payload_hash
            expected_seq += 1
