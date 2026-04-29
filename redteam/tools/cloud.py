"""cloud - read-only enumeration wrappers (AWS / GCP / Azure).

Stub pack. All write/mutation verbs are intentionally absent. Each tool
must scope-check the resource ARN/URN against the engagement target list.
"""

from __future__ import annotations

from typing import Any

from ._context import ToolContext
from ._sdk_shim import create_sdk_mcp_server, tool

PACK_NAME = "cloud"


def build_pack(ctx: ToolContext):
    @tool(
        "cloud__list_buckets",
        "Stub: list S3 / GCS / Azure Blob containers. Read-only.",
        {
            "type": "object",
            "properties": {"provider": {"type": "string", "enum": ["aws", "gcp", "azure"]}},
            "required": ["provider"],
        },
    )
    async def list_buckets(provider: str) -> dict[str, Any]:
        return {
            "provider": provider,
            "status": "not_implemented",
            "hint": "wire to boto3 / google-cloud-storage / azure-storage-blob; credentials from /run/secrets",
        }

    @tool(
        "cloud__describe_iam",
        "Stub: enumerate IAM principals and policies. Read-only.",
        {
            "type": "object",
            "properties": {"provider": {"type": "string", "enum": ["aws", "gcp", "azure"]}},
            "required": ["provider"],
        },
    )
    async def describe_iam(provider: str) -> dict[str, Any]:
        return {"provider": provider, "status": "not_implemented"}

    return create_sdk_mcp_server(
        name="cloud",
        version="0.1.0",
        tools=[list_buckets, describe_iam],
    )
