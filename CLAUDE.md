# CLAUDE.md

Orientation for any Claude session continuing this project.

## What this repo is

A **seed / blueprint** for a modular security testing harness built on
the Claude Agent SDK. It is intentionally not yet functional end-to-end:
the schemas, contracts, file layout, and policy spine are real; many
tool-pack bodies and the runtime wiring are stubs marked clearly.

The full design lives in `docs/PLAN.md`. **Read it before making
non-trivial changes** — most apparent omissions are deliberate v1 scope
cuts, not gaps.

## Hard constraints (do not relax without an explicit user request)

1. **Package name is `redteam`.** Not `harness`, not anything else. The
   filename `docs/PLAN.md` was once `i-want-to-design-modular-squid.md`
   in the planning system; that was a slug artefact, no Squid the proxy
   involvement.
2. **Third-party MCP allowlist is `{atlassian}` only.** Enforced at
   parse time in `redteam/engagement.py::ALLOWED_EXTERNAL_MCPS`. GitHub
   is reached via the `gh` CLI baked into the runtime image — *not* via
   any GitHub MCP. Adding a second provider must be a deliberate code
   change, not a YAML flag flip.
3. **Engagements are signed by SSH keys** (`ssh-keygen -Y sign`)
   verified against `engagements/authorized_signers`. See
   `redteam/auth.py`. No GPG, no sigstore in v1.
4. **Audit-ledger seal is AWS KMS HMAC** (`kms:GenerateMac` /
   `kms:VerifyMac`). See `redteam/ledger/kms_seal.py`. The legacy
   file-key path in `redteam/ledger/chain.py` exists only for local
   pytest; the orchestrator should default to KMS in-container.
5. **Cloud pack is AWS-only.** GCP / Azure are out of scope for v1.
6. **No pause/resume of long engagements** in v1.

## Repo layout (high level)

```
redteam/                package
├── cli.py              click entry point: `redteam run <yaml>`
├── orchestrator.py     ClaudeSDKClient wiring; thin
├── engagement.py       pydantic schema (single source of truth)
├── auth.py             SSH-signature verification (stub)
├── assets.py           read-only mount of pre-cloned repos / IaC / specs
├── budget.py           turn / cost / per-target call accounting
├── mcp_external.py     adapter for the atlassian entry only
├── hooks/              policy spine (scope_guard, audit_writer, redactor, telemetry)
├── ledger/             append-only hash-chained JSONL + KMS seal + verifier
├── tools/              first-party in-process MCP servers (stubbed bodies)
├── subagents/          markdown system prompts for recon / analyst / whitebox / exploiter
└── runtime/            Dockerfile, docker-compose.yml, entrypoint, netpolicy, otel/

engagements/            example.yaml + authorized_signers (SSH allowed-signers)
targets/                operator clones target repos here via `gh repo clone`
tests/                  pytest contracts that pin behaviour; some skip when tools missing
docs/PLAN.md            full design doc
```

## Status: what's real vs. stubbed

**Real and tested:**
- `redteam/engagement.py` — full pydantic schema, allowlist, validators
- `redteam/hooks/scope_guard.py` — URL / CIDR / hostname matchers, deny-wins
- `redteam/ledger/chain.py` — hash-chained append, replay, tamper detection
- `redteam/assets.py` — read-only mount index with metadata
- `redteam/orchestrator.py` — hook dispatch, budget gate, subagent loading

**Stubbed / blueprint-only (clearly marked):**
- `redteam/auth.py` — shells to ssh-keygen but isn't called from the
  parse path yet; wire it into `Engagement.from_yaml`
- `redteam/ledger/kms_seal.py` — boto3 calls sketched; orchestrator
  still uses the file-key path; add a `Sealer` protocol and switch
- `redteam/tools/{recon,web,cloud,network,whitebox,report}.py` — all
  are MCP-shaped but most tool bodies return `not_implemented`
- `redteam/runtime/entrypoint.sh` — netpolicy rendering is a TODO log
- `redteam/runtime/docker-compose.yml` — references `.secrets/` files
  that do not exist; create them before bringing the stack up

## Conventions

- Tool functions take a target via `url` / `target` / `host` / `endpoint`
  / `address` / `cidr` — the scope guard inspects exactly these keys.
- Targetless tools (`report__write_finding`, the `whitebox__*` family)
  are listed explicitly in `redteam/hooks/scope_guard.py::_TARGETLESS_TOOLS`.
- New tool packs go under `redteam/tools/<name>.py`, expose `PACK_NAME`
  and `build_pack(ctx)`, and get listed in `redteam/tools/__init__.py::PACKS`.
- New subagents go under `redteam/subagents/<name>.md` and are loaded
  by name from the engagement YAML.
- Hooks dispatch through `Orchestrator._build_hooks()`; treat that as
  the SDK seam — adapt to the SDK's actual API there, don't sprinkle
  imports across the package.

## Build & test

```bash
pip install -e ".[dev]"                       # install in editable mode
redteam validate engagements/example.yaml      # parse-only check
redteam run engagements/example.yaml --dry-run # build options without calling SDK
pytest                                         # 7 contract test files
```

Container path:

```bash
ENGAGEMENT=engagements/example.yaml \
  docker compose -f redteam/runtime/docker-compose.yml up --abort-on-container-exit redteam
```

## What to build next (suggested order)

1. **Wire `auth.SignatureVerifier` into `Engagement.from_yaml`** so an
   unsigned or bad-signed YAML never reaches the orchestrator.
2. **Add a `Sealer` protocol to `LedgerWriter`** and switch the default
   to `KmsHmacSealer` when `REDTEAM_KMS_KEY_ID` is set, file-key
   otherwise. Update `verify.py` to dispatch on `seal["method"]`.
3. **Render `scope.egress_allowlist` into iptables in `entrypoint.sh`.**
   Right now it only logs.
4. **Implement the recon `gh_*` tools** as wrappers around the `gh` CLI
   so the agent can search the org's GitHub for context without an MCP.
5. **Implement Atlassian MCP wiring + Jira upsert in `report.py`** with
   a deterministic external key (e.g. `redteam-{engagement_id}-{finding_hash[:12]}`)
   so re-runs update tickets idempotently.
6. **Real semgrep / tfsec / checkov calls in `whitebox.py`.**
7. **OTel exporter — confirm SDK env vars and add a starter dashboard
   provisioning file** so `docker compose up` lights up Grafana with
   panels populated.

## What NOT to do

- Don't add a second third-party MCP (no Burp, Shodan, GitLab, etc.).
  If the next session needs one, raise it with the user first.
- Don't replace `gh` CLI with the GitHub MCP. The user explicitly chose
  this tradeoff; revisiting it is a user decision.
- Don't add GCP or Azure to the cloud pack in v1.
- Don't broaden tool allowlists or weaken scope-guard defaults to "make
  things work" during development. The defence-in-depth model (hook is
  the gate, tool is the lock) is load-bearing.
