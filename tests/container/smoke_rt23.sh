#!/usr/bin/env bash
# RT-23 container acceptance check (manual; requires Docker, not run by pytest).
#
# Proves the read-only-rootfs container can actually start the way it would for a
# real engagement: the entrypoint chowns the audit volume, prepares a writable
# SDK state dir ($HOME/.claude) under the read-only rootfs, renders the egress
# allow-list into an nft default-deny ruleset and loads it in-kernel, then drops
# to uid 10001 and runs the CLI. (A real model run needs the `claude` CLI +
# secrets and is out of scope; `validate` exercises the full privileged
# startup path without an SDK call.)
#
# Usage, from the repo root:
#   docker build -f redteam/runtime/Dockerfile -t redteam:0.1.0 .
#   tests/container/smoke_rt23.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
COMPOSE="redteam/runtime/docker-compose.yml"

# Throwaway secrets so compose can mount them (.secrets/ is gitignored). The
# values are never used by `validate`.
mkdir -p .secrets
for s in anthropic_api_key gh_token; do
    [[ -f ".secrets/$s" ]] || echo "smoke-placeholder" > ".secrets/$s"
done

echo "### Running entrypoint privileged startup + redteam validate under read_only rootfs..."
# ENGAGEMENT is the in-CONTAINER path (compose mounts ../../engagements -> /engagements).
# --no-deps: the smoke only needs the redteam container, not the otel collector.
set +e
out="$(ENGAGEMENT=/engagements/example.yaml \
    docker compose -f "$COMPOSE" run --rm --no-deps \
    redteam validate /engagements/example.yaml 2>&1)"
status=$?
set -e
echo "$out"
echo "### container exit: $status"

fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }

[[ $status -eq 0 ]] || fail "container exited non-zero ($status)"
grep -q "egress netpolicy applied" <<<"$out" || fail "netpolicy was not applied"
grep -q "policy drop"             <<<"$out" || fail "in-kernel ruleset missing default-deny (policy drop)"
grep -q "169.254.169.254"         <<<"$out" || fail "in-kernel ruleset missing IMDS deny"
grep -q "OK: ENG-2026-04-001"     <<<"$out" || fail "redteam validate did not succeed as uid 10001"

echo "SMOKE PASS: read-only rootfs boots; HOME+audit writable; nft default-deny (IMDS denied) loaded; CLI ran as uid 10001."
