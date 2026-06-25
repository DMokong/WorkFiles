"""report - canonical finding writer (SARIF) into the audit volume.

Findings are persisted both as SARIF (operator-readable) and into the
ledger (tamper-evident).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "report"

_SEVERITIES = ("info", "low", "medium", "high", "critical")


def build_pack(ctx: ToolContext):
    # No filesystem side effects at build time (keeps --dry-run clean). The
    # SARIF file is created lazily on the first finding.
    sarif_path = Path(ctx.engagement.reporting.destination)
    # Serialize the read-modify-write so concurrent subagent findings can't
    # clobber each other (RT-17/RT-21). The atomic temp+rename below protects
    # against a crash mid-write; the lock protects against interleaving.
    write_lock = asyncio.Lock()

    def _ensure_sarif() -> None:
        if not sarif_path.exists():
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_json(sarif_path, json.loads(_empty_sarif()))

    @tool(
        "report__write_finding",
        "Record a finding (title, severity, evidence). Appends to SARIF + audit ledger.",
        {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": list(_SEVERITIES)},
                "description": {"type": "string"},
                "evidence": {"type": "object"},
                "location": {"type": "string"},
            },
            "required": ["title", "severity", "description"],
        },
    )
    async def write_finding(
        title: str,
        severity: str,
        description: str,
        evidence: dict[str, Any] | None = None,
        location: str | None = None,
    ) -> dict[str, Any]:
        if severity not in _SEVERITIES:
            raise ValueError(f"severity must be one of {_SEVERITIES}")
        finding = {
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence or {},
            "location": location,
            "ts": datetime.now(timezone.utc).isoformat(),
            "engagement_id": ctx.engagement.id,
        }
        async with write_lock:
            ctx.audit.record_finding(finding)
            _ensure_sarif()
            _append_sarif_result(sarif_path, finding)
        return {"recorded": True, "title": title, "severity": severity}

    return create_sdk_mcp_server(
        name="report",
        version="0.1.0",
        tools=[write_finding],
    )


def _empty_sarif() -> str:
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "redteam",
                            "version": "0.1.0",
                            "informationUri": "https://example.invalid/redteam",
                        }
                    },
                    "results": [],
                }
            ],
        },
        indent=2,
    )


def _atomic_write_json(path: Path, obj: Any) -> None:
    """Write JSON to ``path`` atomically: serialize, write a temp file in the
    same directory, fsync, then ``os.replace``.

    Serializing first means an un-encodable object raises before any file is
    touched (the existing file and disk stay clean). The temp+rename means a
    crash mid-write can never leave a half-written/corrupt SARIF doc.
    """
    data = json.dumps(obj, indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _append_sarif_result(path: Path, finding: dict[str, Any]) -> None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # The base file was corrupted out-of-band. Quarantine it and start a
        # fresh SARIF so this finding still lands (the ledger remains the
        # authoritative, tamper-evident record).
        with contextlib.suppress(OSError):
            path.replace(path.with_name(path.name + ".corrupt"))
        doc = json.loads(_empty_sarif())
    level = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}[
        finding["severity"]
    ]
    result = {
        "ruleId": finding["title"],
        "level": level,
        "message": {"text": finding["description"]},
        "properties": {
            "severity": finding["severity"],
            "evidence": finding["evidence"],
            "ts": finding["ts"],
            "engagement_id": finding["engagement_id"],
        },
    }
    if finding.get("location"):
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": finding["location"]}}}
        ]
    doc["runs"][0]["results"].append(result)
    _atomic_write_json(path, doc)
