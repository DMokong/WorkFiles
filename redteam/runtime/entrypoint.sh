#!/usr/bin/env bash
# Container entrypoint. Runs first as root to do the three things that need
# privilege -- fix audit-volume ownership, render+apply the egress netpolicy,
# and prepare a writable SDK state dir under the read-only rootfs -- then drops
# to the unprivileged `redteam` user (uid 10001) via gosu and execs the CLI.
set -euo pipefail

# The rootfs is read-only; the SDK (and the `claude` CLI it spawns) write session
# JSONL under $HOME/.claude. Point HOME at the tmpfs mounted for it so those
# writes succeed; CLAUDE_CONFIG_DIR makes the location explicit to the SDK
# (claude_agent_sdk falls back to $HOME/.claude when it is unset).
export HOME="${REDTEAM_HOME:-/home/redteam}"
export CLAUDE_CONFIG_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

# Single source of truth for the engagement path. The egress netpolicy MUST be
# rendered from the SAME engagement the CLI runs against, or the in-kernel
# allow-list and the engagement's scope can silently disagree. The CLI takes the
# engagement as its sole positional argument, so:
#   - if the caller passed an explicit engagement file in the args, use that;
#   - otherwise fall back to $ENGAGEMENT_FILE and append it to the CLI args.
ENGAGEMENT_FILE="${ENGAGEMENT_FILE:-/engagement.yaml}"
NETPOLICY_FILE="${NETPOLICY_FILE:-/opt/redteam/netpolicy.json}"

caller_passed_engagement() {
    local a
    for a in "$@"; do [[ -f "$a" ]] && return 0; done
    return 1
}

resolve_engagement() {  # echoes the engagement path the CLI will actually use
    local eff="$ENGAGEMENT_FILE" a
    for a in "$@"; do [[ -f "$a" ]] && eff="$a"; done
    printf '%s' "$eff"
}

EFFECTIVE_ENGAGEMENT="$(resolve_engagement "$@")"

if [[ "$(id -u)" == "0" ]]; then
    # --- audit volume: a named volume mounts root:root over the image's /audit,
    # so the non-root user cannot append the ledger unless we chown it first.
    mkdir -p /audit && chown redteam:redteam /audit
    if ! gosu redteam sh -c ': > /audit/.startup-probe && rm -f /audit/.startup-probe'; then
        echo "entrypoint: FATAL: audit dir /audit is not writable by uid 10001" >&2
        exit 72
    fi

    # --- writable SDK state dir. The tmpfs for $HOME also mounts root-owned.
    mkdir -p "$CLAUDE_CONFIG_DIR"
    chown -R redteam:redteam "$HOME"
    # Prove uid 10001 can actually write it under the read-only rootfs; fail
    # closed if not, rather than discovering it mid-run (RT-23).
    if ! gosu redteam sh -c ': > "$CLAUDE_CONFIG_DIR/.startup-probe" && rm -f "$CLAUDE_CONFIG_DIR/.startup-probe"'; then
        echo "entrypoint: FATAL: SDK state dir $CLAUDE_CONFIG_DIR is not writable by uid 10001" >&2
        exit 71
    fi

    # --- egress netpolicy: render the EFFECTIVE engagement's scope.egress_allowlist
    # into an nft ruleset and load it (default-deny; IMDS dropped first). Needs
    # NET_ADMIN, which we hold as root here. Fail closed unless explicitly made
    # optional for a dev box whose kernel lacks nf_tables.
    if [[ -f "$EFFECTIVE_ENGAGEMENT" && -f "$NETPOLICY_FILE" ]]; then
        if command -v nft >/dev/null 2>&1 \
            && python -m redteam.runtime.render_netpolicy "$NETPOLICY_FILE" "$EFFECTIVE_ENGAGEMENT" | nft -f -; then
            echo "entrypoint: egress netpolicy applied from $EFFECTIVE_ENGAGEMENT:" >&2
            nft list ruleset >&2 || true
        else
            echo "entrypoint: FATAL: could not render/apply egress netpolicy" >&2
            if [[ "${REDTEAM_NETPOLICY_OPTIONAL:-0}" != "1" ]]; then
                exit 70
            fi
            echo "entrypoint: REDTEAM_NETPOLICY_OPTIONAL=1 -> continuing WITHOUT egress enforcement (dev only)" >&2
        fi
    else
        echo "entrypoint: FATAL: engagement ($EFFECTIVE_ENGAGEMENT) or netpolicy ($NETPOLICY_FILE) missing" >&2
        exit 70
    fi

    exec gosu redteam "$0" "$@"
fi

# --- unprivileged from here on -------------------------------------------------
if [[ ! -f "$EFFECTIVE_ENGAGEMENT" ]]; then
    echo "entrypoint: engagement file not found at $EFFECTIVE_ENGAGEMENT" >&2
    exit 64
fi

# Run against the SAME engagement the netpolicy was rendered from: pass the
# caller's args through, appending $ENGAGEMENT_FILE only when no explicit
# engagement path was given (so `CMD ["run"]` becomes `run $ENGAGEMENT_FILE`).
if caller_passed_engagement "$@"; then
    exec redteam "$@"
else
    exec redteam "$@" "$ENGAGEMENT_FILE"
fi
