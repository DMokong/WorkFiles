"""report - canonical finding writer (SARIF) into the audit volume.

Findings are persisted both as SARIF (operator-readable) and into the
ledger (tamper-evident).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "report"

_SEVERITIES = ("info", "low", "medium", "high", "critical")


def build_pack(ctx: ToolContext):
    sarif_path = Path(ctx.engagement.reporting.destination)
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    if not sarif_path.exists():
        sarif_path.write_text(_empty_sarif(), encoding="utf-8")

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
        ctx.audit.record_finding(finding)
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


def _append_sarif_result(path: Path, finding: dict[str, Any]) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
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
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
