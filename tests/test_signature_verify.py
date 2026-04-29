"""SSH-signature verification stub.

These tests pin the contract: SignatureVerifier shells to ssh-keygen,
returns a structured result, never raises on a bad signature.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from redteam.auth import SignatureVerifier


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="ssh-keygen not on PATH")
def test_missing_allowed_signers_returns_failure(tmp_path: Path) -> None:
    verifier = SignatureVerifier(allowed_signers=tmp_path / "does-not-exist")
    result = verifier.verify(
        principal="alice@example.com",
        body=b"engagement body",
        armored_signature="-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n",
    )
    assert result.ok is False
    assert "not found" in result.detail


def test_no_ssh_keygen_returns_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    verifier = SignatureVerifier(allowed_signers=tmp_path / "signers")
    result = verifier.verify(
        principal="alice@example.com",
        body=b"x",
        armored_signature="-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n",
    )
    assert result.ok is False
    assert "ssh-keygen" in result.detail
