#!/usr/bin/env bash
# Container entrypoint: chown the audit volume + render egress netpolicy (as
# root), then drop to the unprivileged `redteam` user and exec the CLI.
set -euo pipefail

# Privileged setup, then drop privileges. A named `audit` volume mounts as
# root:root over the image's /audit, so the non-root user cannot write the
# ledger unless we fix ownership first. Re-exec self as `redteam` via gosu.
if [[ "$(id -u)" == "0" ]]; then
    mkdir -p /audit && chown redteam:redteam /audit
    # (netpolicy rendering, which also needs root, belongs here too.)
    exec gosu redteam "$0" "$@"
fi

ENGAGEMENT_FILE="${ENGAGEMENT_FILE:-/engagement.yaml}"

if [[ ! -f "$ENGAGEMENT_FILE" ]]; then
    echo "entrypoint: engagement file not found at $ENGAGEMENT_FILE" >&2
    exit 64
fi

# Blueprint stub: the next iteration should render the egress allowlist
# from $ENGAGEMENT_FILE into iptables/nftables rules. Today this just
# logs the intended behaviour; default-deny is enforced by the host
# network policy / cloud security group.
python -c "
import sys, yaml
spec = yaml.safe_load(open('$ENGAGEMENT_FILE'))
hosts = spec.get('scope', {}).get('egress_allowlist', [])
print(f'entrypoint: would allow egress to {hosts}', file=sys.stderr)
" || true

exec redteam "$@"
