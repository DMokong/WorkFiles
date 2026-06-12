"""Engagement spec - pydantic schema for the YAML control file.

Single source of truth for scope, assets, external MCP, budget. All hooks
read from a parsed Engagement at runtime; nothing else parses the YAML.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

import yaml
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

# Hard allowlist: v1 supports exactly ONE third-party MCP (Atlassian Rovo).
# GitHub is handled via the `gh` CLI baked into the runtime image, not via
# an MCP server. Adding a second provider must be a deliberate code change
# here, not a YAML flag flip.
ALLOWED_EXTERNAL_MCPS: frozenset[str] = frozenset({"atlassian"})


class Window(BaseModel):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _ordered(self) -> "Window":
        if self.end <= self.start:
            raise ValueError("window.end must be after window.start")
        return self

    def covers(self, ts: datetime) -> bool:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return self.start <= ts <= self.end


class Scope(BaseModel):
    targets: list[str] = Field(min_length=1)
    out_of_scope: list[str] = Field(default_factory=list)
    egress_allowlist: list[str] = Field(default_factory=list)

    @field_validator("targets", "out_of_scope")
    @classmethod
    def _validate_target_strings(cls, values: list[str]) -> list[str]:
        for v in values:
            if not v:
                raise ValueError("empty target entry")
            if "://" in v:
                parsed = urlparse(v)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError(f"invalid URL target: {v!r}")
            else:
                try:
                    ipaddress.ip_network(v, strict=False)
                except ValueError:
                    if not _looks_like_hostname(v):
                        raise ValueError(
                            f"target {v!r} is neither a CIDR nor a hostname"
                        )
        return values

    @field_validator("egress_allowlist")
    @classmethod
    def _validate_egress(cls, values: list[str]) -> list[str]:
        for v in values:
            if not _looks_like_hostname(v) and not _is_cidr(v):
                raise ValueError(f"egress entry {v!r} must be host or CIDR")
        return values


def _looks_like_hostname(s: str) -> bool:
    if not s or len(s) > 253:
        return False
    labels = s.split(".")
    return all(label and len(label) <= 63 for label in labels)


def _is_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


class SourceRepo(BaseModel):
    path: Path
    language: str
    role: str


class IacAsset(BaseModel):
    path: Path
    kind: Literal["terraform", "kubernetes", "cloudformation", "pulumi", "ansible"]


class SpecAsset(BaseModel):
    path: Path
    kind: Literal["openapi", "graphql", "asyncapi", "protobuf"]


class ArtefactAsset(BaseModel):
    path: Path
    kind: Literal["cyclonedx", "spdx", "image", "binary"]


class Assets(BaseModel):
    source_repos: list[SourceRepo] = Field(default_factory=list)
    iac: list[IacAsset] = Field(default_factory=list)
    specs: list[SpecAsset] = Field(default_factory=list)
    artefacts: list[ArtefactAsset] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.source_repos or self.iac or self.specs or self.artefacts)

    def all_paths(self) -> list[Path]:
        out: list[Path] = []
        out.extend(r.path for r in self.source_repos)
        out.extend(i.path for i in self.iac)
        out.extend(s.path for s in self.specs)
        out.extend(a.path for a in self.artefacts)
        return out


class Budget(BaseModel):
    max_turns: int = Field(gt=0, le=10_000)
    max_usd: float = Field(gt=0, le=10_000)
    max_tool_calls_per_target: int = Field(gt=0, le=100_000)


class ExternalMcpTransport(str, Enum):
    stdio = "stdio"
    http = "http"
    sse = "sse"


class ExternalMcp(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=32)]
    transport: ExternalMcpTransport
    url: str | None = None
    command: list[str] | None = None
    allowed_tools: list[str] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def _allowlisted(cls, v: str) -> str:
        if v not in ALLOWED_EXTERNAL_MCPS:
            raise ValueError(
                f"external_mcp.name {v!r} not in allowlist "
                f"{sorted(ALLOWED_EXTERNAL_MCPS)} - "
                "third-party MCPs other than Atlassian Rovo require a code change. "
                "GitHub is handled via the `gh` CLI in the runtime image, not via MCP."
            )
        return v

    @model_validator(mode="after")
    def _transport_consistent(self) -> "ExternalMcp":
        if self.transport == ExternalMcpTransport.stdio:
            if not self.command:
                raise ValueError("stdio transport requires `command`")
            if self.url:
                raise ValueError("stdio transport must not set `url`")
        else:
            if not self.url:
                raise ValueError(f"{self.transport.value} transport requires `url`")
            if self.command:
                raise ValueError(
                    f"{self.transport.value} transport must not set `command`"
                )
        return self


class Reporting(BaseModel):
    format: Literal["sarif", "json", "markdown"] = "sarif"
    destination: Path = Path("/audit/findings.sarif")


class Engagement(BaseModel):
    id: Annotated[str, StringConstraints(pattern=r"^[A-Z0-9][A-Z0-9\-_]{2,63}$")]
    operator: EmailStr
    # The engagement is signed with a *detached* sidecar (<file>.sig) verified
    # against `operator`, not an embedded field - see redteam/auth.py. An
    # embedded signature can't sign the bytes it lives in (chicken-and-egg).
    authorized_by: EmailStr
    window: Window
    scope: Scope
    assets: Assets = Field(default_factory=Assets)
    budget: Budget
    tools: list[str] = Field(min_length=1)
    subagents: list[str] = Field(default_factory=list)
    external_mcp: list[ExternalMcp] = Field(default_factory=list)
    objective: Annotated[str, StringConstraints(min_length=20, max_length=8000)]
    reporting: Reporting = Field(default_factory=Reporting)

    @model_validator(mode="after")
    def _whitebox_needs_assets(self) -> "Engagement":
        if "whitebox" in self.tools and self.assets.is_empty():
            raise ValueError(
                "tool 'whitebox' requested but no assets provided - "
                "whitebox tooling needs at least one source_repos / iac / specs / artefacts entry"
            )
        return self

    @model_validator(mode="after")
    def _external_mcp_egress(self) -> "Engagement":
        for mcp in self.external_mcp:
            if mcp.transport in (ExternalMcpTransport.http, ExternalMcpTransport.sse):
                host = urlparse(mcp.url or "").hostname or ""
                if host and host not in self.scope.egress_allowlist:
                    raise ValueError(
                        f"external_mcp[{mcp.name}] host {host!r} must appear in "
                        "scope.egress_allowlist or netpolicy will drop it"
                    )
        return self

    @classmethod
    def from_yaml(cls, path: Path | str) -> "Engagement":
        raw = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: root must be a mapping")
        return cls.model_validate(data)
