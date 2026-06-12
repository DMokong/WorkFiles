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


def signature_path_for(engagement_file: Path | str) -> Path:
    """The detached signature sidecar for an engagement file (``<file>.sig``)."""
    p = Path(engagement_file)
    return p.with_name(p.name + ".sig")


def verify_engagement_file(
    engagement_file: Path | str,
    operator: str,
    allowed_signers: Path = DEFAULT_ALLOWED_SIGNERS,
    namespace: str = DEFAULT_NAMESPACE,
) -> VerificationResult:
    """Verify an engagement's *detached* signature against its operator.

    The signature lives in a sibling ``<engagement>.sig`` file produced by
    ``ssh-keygen -Y sign`` over the exact engagement-file bytes. This avoids the
    chicken-and-egg of embedding a signature inside the bytes it signs, and the
    signer principal is bound to the engagement's declared ``operator`` (so a
    valid signature from a different authorised principal is still rejected).
    """
    engagement_file = Path(engagement_file)
    sig = signature_path_for(engagement_file)
    if not sig.is_file():
        return VerificationResult(
            ok=False,
            principal=operator,
            detail=f"detached signature not found: {sig} "
            f"(sign with: ssh-keygen -Y sign -f <key> -n {namespace} {engagement_file})",
        )
    body = engagement_file.read_bytes()
    armored = sig.read_text(encoding="utf-8")
    return SignatureVerifier(allowed_signers=allowed_signers, namespace=namespace).verify(
        principal=operator, body=body, armored_signature=armored
    )
