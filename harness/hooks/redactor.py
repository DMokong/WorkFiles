"""Redactor - strips obvious secrets from tool responses before telemetry.

The ledger keeps the raw payload hash so a redacted entry is still
verifiable, but the body that reaches OTel/Grafana has secrets masked.
"""

from __future__ import annotations

import re
from typing import Any

# Conservative patterns - false negatives are fine, false positives in the
# audit trail are not. Tune in production with operator feedback.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"\b[A-Za-z0-9/+=]{40}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_fine_grained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("authorization_header", re.compile(r"(?i)\b(authorization|bearer)\s*[:=]\s*[A-Za-z0-9._\-]{20,}")),
]


class Redactor:
    def __init__(self, extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None):
        self._patterns = list(_PATTERNS) + list(extra_patterns or [])

    def scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._scrub_str(value)
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        return value

    def _scrub_str(self, s: str) -> str:
        out = s
        for label, pat in self._patterns:
            out = pat.sub(f"[REDACTED:{label}]", out)
        return out
