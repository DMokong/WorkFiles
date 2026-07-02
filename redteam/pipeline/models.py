"""Pydantic data model for the triage pipeline.

The finding *input* fields (title, severity, description, evidence, location,
vuln_class, ts) have *tolerant* validators: a malformed / hostile value coerces
or degrades to a safe value, never raises. The pipeline treats these findings as
untrusted input (they came from an LLM). ``vuln_class`` is normally derived from
keywords rather than supplied. The internal enrichment/verify fields are set by
the pipeline itself, never imported from the untrusted ledger (see load.py — it
whitelists only the fields the agent's report tool writes), so they need no
coercion.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, field_validator

from . import cwe

Severity = Literal["info", "low", "medium", "high", "critical"]
_SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# "file:line" or "file:start-end" — split on the LAST colon so paths that
# themselves contain a colon (e.g. a drive letter) still parse. Line numbers are
# bounded to 9 digits: a longer run of digits is meaningless as a line and would
# otherwise raise on int() (Py3.14 caps int(str) at 4300 digits), so it falls
# through to None (BAD_LOCATION) instead of crashing a "total" stage.
_LINESPEC = re.compile(r"^(\d{1,9})(?:-(\d{1,9}))?$")

DropReason = Literal[
    "NO_EVIDENCE",
    "BAD_LOCATION",
    "FILE_NOT_FOUND",
    "DUPLICATE",
    "FALSE_POSITIVE",
    "UNCONFIRMED",
]
Verdict = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "UNVERIFIED"]


class DupLocation(BaseModel):
    file: str
    line: int | None = None


class Finding(BaseModel):
    # --- from the agent (report__write_finding) ---
    title: str = "untitled finding"
    severity: Severity = "info"
    description: str = ""
    evidence: dict = {}
    location: str | None = None  # "file:line" or "file:start-end"
    vuln_class: str | None = None  # derived from keywords if absent
    ts: str | None = None
    # --- deterministic enrichment ---
    cwe: str | None = None  # "CWE-89"
    cwe_name: str | None = None
    cvss_vector: str | None = None  # "CVSS:3.1/AV:N/..."
    cvss_score: float | None = None
    cvss_rating: str | None = None  # Critical/High/Medium/Low/None
    cvss_source: Literal["vector", "severity_band"] | None = None
    # environmental CVSS 3.1 (modified base + security requirements)
    cvss_environmental_score: float | None = None
    cvss_environmental_rating: str | None = None
    # --- dedup ---
    duplicates: list[DupLocation] = []
    # --- verify (opt-in) ---
    verdict: Verdict | None = None
    verdict_confidence: int | None = None  # 0..10
    verdict_reason: str = ""
    # --- offensive priority (deterministic; computed after chains) ---
    priority_score: int | None = None  # 0..100
    priority_rating: str | None = None  # P1 (act now) .. P4

    @field_validator("title", mode="before")
    @classmethod
    def _coerce_title(cls, v: object) -> str:
        s = "" if v is None else str(v)
        return s.strip() or "untitled finding"

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v: object) -> str:
        if not isinstance(v, str):
            return "info"
        s = v.strip().lower()
        return s if s in _SEVERITIES else "info"

    @field_validator("description", "verdict_reason", mode="before")
    @classmethod
    def _coerce_text(cls, v: object) -> str:
        return "" if v is None else str(v)

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: object) -> dict:
        return v if isinstance(v, dict) else {}

    @field_validator("location", "vuln_class", "ts", "cwe", "cwe_name", mode="before")
    @classmethod
    def _coerce_optional_str(cls, v: object) -> str | None:
        return None if v is None else str(v)

    def parsed_location(self) -> tuple[str, int, int] | None:
        """``(file, start_line, end_line)`` or None if absent / not line-shaped."""
        if not self.location or ":" not in self.location:
            return None
        file, _, spec = self.location.rpartition(":")
        m = _LINESPEC.match(spec.strip())
        if not file.strip() or not m:
            return None
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        if end < start:  # tolerate a reversed range (e.g. "30-20")
            start, end = end, start
        return file.strip(), start, end

    @property
    def line_no(self) -> int | None:
        parsed = self.parsed_location()
        return parsed[1] if parsed else None

    def derived_vuln_class(self) -> str:
        """The finding's class: the explicit label if set, else keyword-derived."""
        if self.vuln_class:
            return self.vuln_class
        return cwe.classify(f"{self.title} {self.description}")

    def canonical_key(self, line_bucket: int = 10) -> tuple:
        """Coarse dedup grouping key: ``(file, line // bucket, vuln_class)``.

        File and bucket are None when the finding has no parseable location;
        dedup refines within a group by line tolerance separately.
        """
        parsed = self.parsed_location()
        file = parsed[0] if parsed else None
        bucket = parsed[1] // line_bucket if parsed else None
        return (file, bucket, self.derived_vuln_class())


class Chain(BaseModel):
    title: str = "exploit chain"
    steps: list[int] = []  # indices into the final ranked findings (>=2, validated in stage)
    severity: str = "info"
    narrative: str = ""

    @field_validator("steps", mode="before")
    @classmethod
    def _coerce_steps(cls, v: object) -> list[int]:
        if not isinstance(v, (list, tuple)):
            return []
        out: list[int] = []
        for x in v:
            try:
                out.append(int(x))
            except (TypeError, ValueError):
                continue
        return out


class DroppedFinding(BaseModel):
    finding: Finding
    reason: DropReason
    detail: str = ""


class TriageReport(BaseModel):
    engagement_id: str
    findings: list[Finding] = []  # canonical, kept (verified if --verify)
    dropped: list[DroppedFinding] = []
    chains: list[Chain] = []
    metrics: dict = {}
    degraded: bool = False
    degraded_reason: str = ""
