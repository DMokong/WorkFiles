"""Load ``finding.recorded`` entries out of a sealed engagement ledger.

Read-only over the authoritative record: this module never writes to, mutates,
or re-seals the ledger. Parsing is tolerant — a corrupt line or a malformed
finding is skipped (and logged), never fatal.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .models import Finding

logger = logging.getLogger(__name__)

# Only these fields are imported from the (untrusted) ledger. Enrichment/verify
# fields (cwe*, cvss*, verdict*, duplicates) are set by the pipeline itself; a
# tampered ledger must not be able to inject a verify-grade CVSS vector or a
# forged verdict that later stages would trust.
_AGENT_FIELDS = ("title", "severity", "description", "evidence", "location", "ts", "engagement_id")


def findings_from_ledger(ledger_path: Path) -> tuple[str, list[Finding]]:
    """Return ``(engagement_id, findings)`` parsed from a ledger JSONL file.

    The engagement id comes from the ``session.start`` record when present, else
    falls back to the first finding's own ``engagement_id`` (else ``""``).
    """
    session_id = ""
    first_finding_id = ""
    findings: list[Finding] = []

    try:
        # errors="replace" so a single stray non-UTF-8 byte corrupts at most its
        # own line (which then fails json.loads and is skipped) rather than
        # aborting the whole load.
        text = Path(ledger_path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("triage: cannot read ledger %s: %s", ledger_path, e)
        return "", findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            logger.warning("triage: skipping unparseable ledger line %d", lineno)
            continue
        if not isinstance(rec, dict):
            continue
        payload = rec.get("payload", rec)
        if not isinstance(payload, dict):
            continue
        kind = payload.get("kind")

        if kind == "session.start" and not session_id:
            eng = payload.get("engagement")
            if isinstance(eng, dict) and eng.get("id"):
                session_id = str(eng["id"])
            continue

        if kind == "finding.recorded":
            raw = payload.get("finding")
            if not isinstance(raw, dict):
                logger.warning("triage: skipping non-dict finding at line %d", lineno)
                continue
            agent_view = {k: raw[k] for k in _AGENT_FIELDS if k in raw}
            try:
                finding = Finding.model_validate(agent_view)
            except Exception as e:  # noqa: BLE001 - loader must never crash on one bad finding
                logger.warning("triage: skipping malformed finding at line %d: %s", lineno, e)
                continue
            findings.append(finding)
            if not first_finding_id and raw.get("engagement_id"):
                first_finding_id = str(raw["engagement_id"])

    # session.start is authoritative when present, regardless of line order.
    return session_id or first_finding_id, findings
