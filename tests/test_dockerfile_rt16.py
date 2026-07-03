"""RT-16: the runtime Dockerfile pins + verifies its scanner supply chain.

Contract over the shipped Dockerfile (no build here — the build is exercised
separately). Guards against the regressions RT-16 flagged: an unquoted
`semgrep>=…` the shell reads as a redirection (silently dropping the pin),
`releases/latest` binaries, un-checksummed downloads, and a floating base image.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = (
    Path(__file__).resolve().parent.parent / "redteam" / "runtime" / "Dockerfile"
).read_text()

# What the shell actually executes — comment lines (which describe the very
# anti-patterns we forbid) are stripped so a doc line can't trip the guards.
EXEC = "\n".join(ln for ln in DOCKERFILE.splitlines() if not ln.lstrip().startswith("#"))


def test_base_image_is_digest_pinned():
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}", DOCKERFILE, re.M)


def test_no_unpinned_latest_binary_pulls():
    assert "releases/latest/download" not in EXEC
    # awscli must be the versioned zip, never the floating one.
    assert "awscli-exe-linux-x86_64.zip" not in EXEC
    assert "awscli-exe-linux-x86_64-${AWSCLI_VERSION}.zip" in EXEC


def test_pip_scanner_specs_are_quoted_and_exact_pinned():
    # The RT-16 bug: an unquoted `>=` version floor is parsed by the shell as a
    # redirection (`> =…`), silently dropping the pin.
    assert '"semgrep==${SEMGREP_VERSION}"' in EXEC
    assert '"checkov==${CHECKOV_VERSION}"' in EXEC
    # No bare/unquoted `>=` version floor for either scanner in executed lines.
    assert not re.search(r"[^\"']semgrep>=", EXEC)
    assert not re.search(r"[^\"']checkov>=", EXEC)


def test_downloads_are_checksum_verified():
    # Both the awscli zip and the tfsec tarball are SHA256-checked before use.
    assert EXEC.count("sha256sum -c -") >= 2
    assert re.search(r"AWSCLI_SHA256=[0-9a-f]{64}", EXEC)
    assert re.search(r"TFSEC_SHA256=[0-9a-f]{64}", EXEC)


def test_kube_linter_not_installed():
    # It may be mentioned in a comment (explaining its removal) but never installed.
    assert "kube-linter" not in EXEC


def test_whitebox_scanners_present():
    # The three scanners the whitebox pack (build-next #6) shells out to — checked
    # against executed lines (not comments) so a deleted install can't false-pass
    # on a lingering comment mention.
    for tool in ("semgrep", "checkov", "tfsec"):
        assert tool in EXEC, f"{tool} must be installed in the image"
    # Each install is smoke-checked in-build so a broken layer fails the build.
    for check in ("semgrep --version", "checkov --version", "tfsec --version"):
        assert check in EXEC
