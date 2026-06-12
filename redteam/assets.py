"""Read-only assets mount + indexing.

Operator-supplied source repos, IaC, specs, and artefacts are bind-mounted
read-only under /assets/ inside the container. This module validates each
path on the host side and produces an index the whitebox tool pack reads.

Read-only enforcement happens at the container layer (ro bind mount); the
tool pack additionally refuses any write call as defence in depth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .engagement import Assets

CONTAINER_ASSETS_ROOT = Path("/assets")


@dataclass(frozen=True)
class AssetEntry:
    container_path: Path
    host_path: Path
    kind: Literal["source", "iac", "spec", "artefact"]
    metadata: dict[str, Any]


@dataclass
class AssetIndex:
    entries: list[AssetEntry] = field(default_factory=list)

    def by_kind(self, kind: str) -> list[AssetEntry]:
        return [e for e in self.entries if e.kind == kind]

    def container_paths(self) -> list[Path]:
        return [e.container_path for e in self.entries]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [
                {
                    "container_path": str(e.container_path),
                    "host_path": str(e.host_path),
                    "kind": e.kind,
                    "metadata": e.metadata,
                }
                for e in self.entries
            ],
            "count": len(self.entries),
        }


def build_index(
    assets: Assets, host_root: Path | None = None, require_exists: bool = True
) -> AssetIndex:
    """Build a container-path index of the engagement's assets.

    `host_root` is the directory relative paths resolve against (the dir the
    operator runs `redteam` from, where ./targets was cloned). Each entry gets
    a stable container-side path under /assets/<kind>/<role-or-name>.

    When `require_exists` is False (used at construction time, e.g. --dry-run),
    missing paths do not raise - the index is still built with minimal
    metadata. A real run validates existence via assert_assets_exist().
    """
    host_root = (host_root or Path.cwd()).resolve()
    index = AssetIndex()

    for repo in assets.source_repos:
        host = _resolve(host_root, repo.path, require_exists)
        meta = _index_source_repo(host, repo.language) if host.is_dir() else {"present": host.exists()}
        meta["language"] = repo.language
        meta["role"] = repo.role
        index.entries.append(
            AssetEntry(
                container_path=CONTAINER_ASSETS_ROOT / "source" / repo.role,
                host_path=host,
                kind="source",
                metadata=meta,
            )
        )

    for iac in assets.iac:
        host = _resolve(host_root, iac.path, require_exists)
        index.entries.append(
            AssetEntry(
                container_path=CONTAINER_ASSETS_ROOT / "iac" / iac.kind / host.name,
                host_path=host,
                kind="iac",
                metadata={"kind": iac.kind, "file_count": _count_files(host) if host.exists() else 0},
            )
        )

    for spec in assets.specs:
        host = _resolve(host_root, spec.path, require_exists)
        index.entries.append(
            AssetEntry(
                container_path=CONTAINER_ASSETS_ROOT / "specs" / spec.kind / host.name,
                host_path=host,
                kind="spec",
                metadata={"kind": spec.kind, "size": host.stat().st_size if host.is_file() else None},
            )
        )

    for art in assets.artefacts:
        host = _resolve(host_root, art.path, require_exists)
        index.entries.append(
            AssetEntry(
                container_path=CONTAINER_ASSETS_ROOT / "artefacts" / art.kind / host.name,
                host_path=host,
                kind="artefact",
                metadata={"kind": art.kind, "size": host.stat().st_size if host.is_file() else None},
            )
        )

    return index


def assert_assets_exist(index: AssetIndex) -> None:
    """Raise FileNotFoundError if any indexed asset path is missing.

    Called at real-run start so an engagement that references un-cloned repos
    fails early (a --dry-run skips this and tolerates absent assets).
    """
    missing = [str(e.host_path) for e in index.entries if not e.host_path.exists()]
    if missing:
        raise FileNotFoundError(
            "asset paths do not exist (clone them into ./targets first): "
            + ", ".join(missing)
        )


def _resolve(root: Path, p: Path, require_exists: bool) -> Path:
    candidate = p if p.is_absolute() else (root / p)
    candidate = candidate.resolve()
    if require_exists and not candidate.exists():
        raise FileNotFoundError(f"asset path does not exist: {p} (resolved {candidate})")
    return candidate


def _count_files(p: Path) -> int:
    if p.is_file():
        return 1
    return sum(1 for _ in p.rglob("*") if _.is_file())


def _index_source_repo(p: Path, language: str) -> dict[str, Any]:
    if not p.is_dir():
        raise NotADirectoryError(f"source_repos.path must be a directory: {p}")
    file_count = _count_files(p)
    top_level = sorted(child.name for child in p.iterdir() if not child.name.startswith("."))[:32]
    return {
        "file_count": file_count,
        "top_level": top_level,
    }


def docker_mount_args(index: AssetIndex) -> list[str]:
    """Render `docker run` mount arguments for each indexed asset (read-only)."""
    args: list[str] = []
    for entry in index.entries:
        args.extend(
            [
                "--mount",
                f"type=bind,source={entry.host_path},target={entry.container_path},readonly",
            ]
        )
    return args
