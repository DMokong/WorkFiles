# Digest-pinned base (the `3.12-slim` tag floats; the digest makes the build
# reproducible and supply-chain-verifiable). Targets linux/amd64 — the scanner
# and awscli binaries below are amd64. Bump both the tag and digest together.
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

# System tooling we shell out to from tool packs.
# - gh:     GitHub CLI (recon + asset-fetch, authenticated via /run/secrets/gh_token)
# - awscli: AWS read-only enumeration in the cloud pack
# - openssh-client: ssh-keygen -Y verify for engagement signatures
# - whois, dnsutils: recon pack
# - nmap: network pack
# - jq, curl: ad-hoc inspection by the agent
# - nftables: the entrypoint renders scope.egress_allowlist into an nft ruleset
#   (default-deny egress) and loads it before dropping privileges
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        gh \
        git \
        gosu \
        jq \
        nftables \
        nmap \
        openssh-client \
        unzip \
        whois \
    && rm -rf /var/lib/apt/lists/*

# The Claude Agent SDK spawns the `claude` Code CLI as its transport (the SDK
# finds it via PATH / shutil.which). The CLI is a Node package, so install Node
# (NodeSource, GPG-verified apt) and pin the CLI well above the SDK's 2.0.0
# minimum. `claude -v` fails the build if the install is broken. Runtime auth is
# env-configured (direct key, or CLAUDE_CODE_USE_BEDROCK / CLAUDE_CODE_USE_VERTEX).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code@2.1.191 \
    && npm cache clean --force \
    && claude -v

# Pin the CLI's egress to what the engagement authorizes: no telemetry, no
# auto-update, no error reporting / non-essential traffic. This matters most for
# `doctor --probe`, which spawns the CLI with the egress netpolicy NOT applied
# (diagnostics skip it), but it is the right default for the agent run too.
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_ERROR_REPORTING=1

# AWS CLI v2 (boto3 covers most reads; awscli is for ad-hoc agent use in the
# cloud pack). Version-pinned + SHA256-verified (AWS ships no checksums file, so
# the hash of the exact versioned zip is pinned here; verify + bump together).
ARG AWSCLI_VERSION=2.35.14
ARG AWSCLI_SHA256=e8124b5b1cfdf69ec97d95f1b1b1e331afaf4f752b5bca153fa2b354785880f3
RUN curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${AWSCLI_VERSION}.zip" -o /tmp/awscli.zip \
    && echo "${AWSCLI_SHA256}  /tmp/awscli.zip" | sha256sum -c - \
    && unzip -q /tmp/awscli.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/awscli.zip /tmp/aws \
    && aws --version

# Static-analysis scanners for the whitebox pack (semgrep + checkov via pip,
# tfsec as a release binary). EXACT-pinned and quoted — an unquoted `semgrep>=…`
# would be parsed by the shell as a redirection (`> =…`), silently dropping the
# pin (RT-16). `--version` calls fail the build if an install is broken.
ARG SEMGREP_VERSION=1.168.0
ARG CHECKOV_VERSION=3.3.6
RUN pip install --no-cache-dir \
        "semgrep==${SEMGREP_VERSION}" \
        "checkov==${CHECKOV_VERSION}" \
    && semgrep --version \
    && checkov --version

# tfsec: pinned release + SHA256-verified tarball (from the release's published
# checksums), then extract just the `tfsec` binary. kube-linter was removed — it
# was installed from `releases/latest` (unpinned) and never used by any tool pack
# (the whitebox IaC scan uses tfsec for terraform, checkov for kubernetes).
ARG TFSEC_VERSION=1.28.14
ARG TFSEC_SHA256=329ae7f67f2f1813ebe08de498719ea7003c75d3ca24bb0b038369062508008e
RUN curl -fsSL "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec_${TFSEC_VERSION}_linux_amd64.tar.gz" -o /tmp/tfsec.tgz \
    && echo "${TFSEC_SHA256}  /tmp/tfsec.tgz" | sha256sum -c - \
    && tar -xzf /tmp/tfsec.tgz -C /usr/local/bin/ tfsec \
    && chmod +x /usr/local/bin/tfsec \
    && rm -f /tmp/tfsec.tgz \
    && tfsec --version

WORKDIR /opt/redteam
COPY pyproject.toml /opt/redteam/
COPY redteam/ /opt/redteam/redteam/
RUN pip install --no-cache-dir -e .

# Create the unprivileged runtime user. The container starts as root so the
# entrypoint can chown the mounted audit volume (a named volume mounts as root
# regardless of this image's /audit ownership) and then drops to `redteam` via
# gosu - so the run itself is never privileged.
RUN useradd -m -u 10001 -s /usr/sbin/nologin redteam \
    && mkdir -p /audit /assets /run/secrets \
    && chown redteam:redteam /audit

COPY redteam/runtime/entrypoint.sh /opt/redteam/entrypoint.sh
RUN chmod +x /opt/redteam/entrypoint.sh
ENTRYPOINT ["/opt/redteam/entrypoint.sh"]
# Just the subcommand: the entrypoint appends the engagement path from
# $ENGAGEMENT_FILE so the rendered egress netpolicy and the run use the same file.
CMD ["run"]
