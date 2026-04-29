"""Operator engagement-file signature verification.

We sign engagement YAMLs with SSH keys via `ssh-keygen -Y sign` and
verify with `ssh-keygen -Y verify`. Operators already have SSH keys
for GitHub auth, so no new PKI is needed and rotation is a PR against
`engagements/authorized_signers`.

This module is a *blueprint stub*: it shells out to the system
`ssh-keygen` binary (present in the runtime image) and returns a
boolean. The next iteration should:
  - cache the verified principal on the parsed Engagement object
  - record verification outcome to the audit ledger as entry 0
  - support `cert-authority` lines in the allowed-signers file for
    org SSH-CA setups
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_NAMESPACE = "redteam-engagement"
DEFAULT_ALLOWED_SIGNERS = Path("engagements/authorized_signers")


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    principal: str | None
    detail: str


class SignatureVerifier:
    """Verifies an engagement YAML against an allowed-signers file."""

    def __init__(
        self,
        allowed_signers: Path = DEFAULT_ALLOWED_SIGNERS,
        namespace: str = DEFAULT_NAMESPACE,
    ):
        self.allowed_signers = Path(allowed_signers)
        self.namespace = namespace

    def verify(
        self,
        principal: str,
        body: bytes,
        armored_signature: str,
    ) -> VerificationResult:
        """Verify `armored_signature` against `body` for `principal`.

        Shells out to `ssh-keygen -Y verify`. The next implementation
        should bind this directly into the Engagement parse path so an
        unsigned-or-bad-signed YAML never reaches the orchestrator.
        """
        if not shutil.which("ssh-keygen"):
            return VerificationResult(
                ok=False,
                principal=principal,
                detail="ssh-keygen not on PATH (runtime image must include openssh-client)",
            )
        if not self.allowed_signers.is_file():
            return VerificationResult(
                ok=False,
                principal=principal,
                detail=f"allowed_signers file not found: {self.allowed_signers}",
            )

        with tempfile.NamedTemporaryFile("w", suffix=".sig", delete=False) as sig_f:
            sig_f.write(armored_signature)
            sig_path = Path(sig_f.name)

        try:
            proc = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(self.allowed_signers),
                    "-I",
                    principal,
                    "-n",
                    self.namespace,
                    "-s",
                    str(sig_path),
                ],
                input=body,
                capture_output=True,
                check=False,
            )
        finally:
            sig_path.unlink(missing_ok=True)

        if proc.returncode == 0:
            return VerificationResult(
                ok=True,
                principal=principal,
                detail=proc.stdout.decode("utf-8", "replace").strip(),
            )
        return VerificationResult(
            ok=False,
            principal=principal,
            detail=proc.stderr.decode("utf-8", "replace").strip()
            or f"ssh-keygen -Y verify exited {proc.returncode}",
        )
