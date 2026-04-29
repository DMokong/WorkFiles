"""Asset index: validates pre-cloned source/IaC/specs and renders ro mounts."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.assets import build_index, docker_mount_args
from redteam.engagement import Assets, SourceRepo


def test_missing_source_repo_raises(tmp_path: Path) -> None:
    assets = Assets(source_repos=[SourceRepo(path=Path("nope"), language="python", role="backend")])
    with pytest.raises(FileNotFoundError):
        build_index(assets, host_root=tmp_path)


def test_index_lists_source_repo(tmp_path: Path) -> None:
    repo = tmp_path / "example-api"
    repo.mkdir()
    (repo / "main.py").write_text("print('hi')")

    assets = Assets(
        source_repos=[SourceRepo(path=Path("example-api"), language="python", role="backend")]
    )
    index = build_index(assets, host_root=tmp_path)

    assert len(index.entries) == 1
    entry = index.entries[0]
    assert entry.kind == "source"
    assert entry.metadata["language"] == "python"
    assert entry.metadata["file_count"] == 1


def test_docker_mount_args_are_readonly(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    assets = Assets(source_repos=[SourceRepo(path=Path("r"), language="go", role="backend")])
    index = build_index(assets, host_root=tmp_path)
    args = docker_mount_args(index)
    assert "readonly" in args[1]
