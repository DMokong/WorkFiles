FROM python:3.12-slim

# System tooling we shell out to from tool packs.
# - gh:     GitHub CLI (recon + asset-fetch, authenticated via /run/secrets/gh_token)
# - awscli: AWS read-only enumeration in the cloud pack
# - openssh-client: ssh-keygen -Y verify for engagement signatures
# - whois, dnsutils: recon pack
# - nmap: network pack
# - jq, curl: ad-hoc inspection by the agent
# - iptables: rendered netpolicy at entrypoint
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        gh \
        git \
        iptables \
        jq \
        nmap \
        openssh-client \
        unzip \
        whois \
    && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 (boto3 covers most reads; awscli is for ad-hoc agent use).
RUN curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscli.zip \
    && unzip -q /tmp/awscli.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/awscli.zip /tmp/aws

# Static analysis tooling for the whitebox pack.
RUN pip install --no-cache-dir \
        semgrep>=1.70 \
        checkov>=3.2

# tfsec, kube-linter as static binaries.
RUN curl -fsSL "https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64" \
        -o /usr/local/bin/tfsec \
    && chmod +x /usr/local/bin/tfsec \
    && curl -fsSL "https://github.com/stackrox/kube-linter/releases/latest/download/kube-linter-linux.tar.gz" \
        | tar -xz -C /usr/local/bin/ kube-linter

WORKDIR /opt/redteam
COPY pyproject.toml /opt/redteam/
COPY redteam/ /opt/redteam/redteam/
RUN pip install --no-cache-dir -e .

# Non-root runtime; /audit and /tmp are the only writable surfaces.
RUN useradd -m -u 10001 -s /usr/sbin/nologin redteam \
    && mkdir -p /audit /assets /run/secrets \
    && chown redteam:redteam /audit
USER redteam

COPY redteam/runtime/entrypoint.sh /opt/redteam/entrypoint.sh
ENTRYPOINT ["/opt/redteam/entrypoint.sh"]
CMD ["run", "/engagement.yaml"]
