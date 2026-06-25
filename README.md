# redteam

Modular security testing harness on the Claude Agent SDK. **This repo is
a blueprint / seed project**, not a finished product — many module
bodies are stubs. The schemas, contracts, file layout, and policy spine
are real; the rest is signposted for the next implementation phase.

The complete design doc is in [docs/PLAN.md](docs/PLAN.md). Orientation
for any continuing Claude session is in [CLAUDE.md](CLAUDE.md).

## What it is

A controlled, repeatable harness for **authorized** red-team engagements
against systems the operating org owns. The operator declares scope and
an objective in a signed YAML; an agent runs unattended inside an
ephemeral container, with every tool call gated by policy and recorded
in a tamper-evident hash-chained ledger.

The four properties the design protects:

- **Observability** — live OTel + structured tool events to a local /
  central Grafana stack.
- **Auditability** — KMS-sealed, hash-chained JSONL ledger; standalone
  `redteam-verify` CLI.
- **Customisability** — per-engagement scope, tools, egress, subagents.
- **Autonomy** — long unattended runs with budget / turn / per-target
  call caps.

## Quickstart (local)

```bash
pip install -e ".[dev]"

# Parse-only validation of an engagement YAML.
redteam validate engagements/example.yaml

# Build options without invoking the SDK (sanity-check wiring).
redteam run engagements/example.yaml --dry-run

# Check the container/host is ready to run an engagement (no token spend).
# Inside the container, `doctor --probe` also confirms the SDK can spawn the
# `claude` CLI transport. Shows the model backend it would use (direct key, or
# Amazon Bedrock / Google Vertex via CLAUDE_CODE_USE_BEDROCK / _VERTEX).
redteam doctor

# Run the contract test suite.
pytest
```

## Quickstart (container)

```bash
mkdir -p .secrets
echo  "$ANTHROPIC_API_KEY"  > .secrets/anthropic_api_key
echo  "$GH_PAT"             > .secrets/gh_token
chmod 600 .secrets/*

# Pre-clone target repos for the whitebox surface.
gh repo clone myorg/example-api ./targets/example-api

# ENGAGEMENT is the in-CONTAINER path (compose mounts ./engagements at /engagements).
ENGAGEMENT=/engagements/example.yaml \
  docker compose -f redteam/runtime/docker-compose.yml up \
    --abort-on-container-exit redteam
```

Only engagements whose `external_mcp` enables `atlassian` need the
`atlassian_token` secret; create `.secrets/atlassian_token` and add the
overlay `-f redteam/runtime/docker-compose.atlassian.yml`.

The compose stack also brings up an OpenTelemetry collector and a local
Grafana / Tempo dev stack on profile `dev`. In production, point
`CENTRAL_OTLP_ENDPOINT` at the org's central stack.

## Design constraints (binding for v1)

- **Package name** is `redteam`.
- **Third-party MCP allowlist is `{atlassian}` only.** GitHub is reached
  via the `gh` CLI baked into the runtime image — not via any GitHub
  MCP. Enforced at parse time by the pydantic schema.
- **Engagements are signed by SSH keys** verified against
  `engagements/authorized_signers` (`ssh-keygen -Y sign` /
  `ssh-keygen -Y verify`).
- **Audit-ledger seal uses AWS KMS HMAC** (`kms:GenerateMac` /
  `kms:VerifyMac`); the verifier role gets verify-only IAM.
- **Cloud pack is AWS-only.**
- **No pause/resume of long engagements** in v1.

See [docs/PLAN.md](docs/PLAN.md) for the rationale behind each.

## Repo layout

```
redteam/                core package
├── cli.py              `redteam run` / `redteam validate`
├── orchestrator.py     ClaudeSDKClient wiring
├── engagement.py       pydantic schema (single source of truth)
├── auth.py             SSH-signature verification
├── assets.py           read-only mount of source / IaC / specs
├── budget.py           turn / cost / per-target call accounting
├── mcp_external.py     atlassian-only MCP adapter
├── hooks/              scope_guard, audit_writer, redactor, telemetry
├── ledger/             chain + KMS seal + standalone verifier
├── tools/              first-party in-process MCP servers
├── subagents/          markdown system prompts
└── runtime/            Dockerfile, docker-compose, entrypoint, netpolicy, otel/

engagements/            example.yaml + authorized_signers
targets/                operator clones target repos here via `gh`
tests/                  contract tests
docs/PLAN.md            full design doc
CLAUDE.md               orientation for continuing AI sessions
```

## Status

Maturing blueprint, built cage-first. Real and tested: the schemas, scope
guard, hash-chained ledger, orchestrator/SDK wiring, the egress netpolicy
renderer (RT-23), the atomic SARIF report writer (RT-21), and the
whitebox/web tool bodies. The runtime image now ships Node + the `claude`
CLI (the Agent SDK's transport), so the container runs a contained
engagement end-to-end — use `redteam doctor --probe` to confirm readiness,
and `engagements/whitebox-first.example.yaml` for the first contained run.
A true *autonomous* run needs a model backend (`ANTHROPIC_API_KEY`, or
Amazon Bedrock / Google Vertex via `CLAUDE_CODE_USE_BEDROCK` / `_VERTEX`).
Still stubbed and clearly marked: the recon/cloud/network tool bodies, the
KMS sealer, the SSH-sig parse hook, and the verify/dedup/enrich finding
pipeline.
[CLAUDE.md](CLAUDE.md) lists the suggested next-steps order.
