#!/usr/bin/env bash
# Container entrypoint: render egress netpolicy from engagement YAML, then
# exec the redteam CLI. Runs as the non-root `redteam` user; netpolicy
# rendering uses CAP_NET_ADMIN granted in compose.
set -euo pipefail

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
