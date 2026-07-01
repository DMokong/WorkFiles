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

## Triage — refine an engagement's findings

An engagement records raw findings into the sealed ledger. `redteam triage`
turns those into a **trustworthy** report: deduplicated, CWE/CVSS-enriched,
optionally verified and composed into exploit chains. It reads the ledger
**read-only** (never mutates or re-seals it) and writes three artifacts next to
it (or under `--out`):

- `<ledger>.triaged.sarif` — refined SARIF 2.1.0 (one result per kept finding,
  CWE taxonomy, CVSS + verdict in `properties`, dedup `relatedLocations`),
- `<ledger>.report.md` — a human-readable summary + findings table + exploit
  chains + a dropped-findings appendix,
- `<ledger>.triage.json` — the full structured report.

```bash
# Deterministic stages only (prefilter → dedup → enrich → emit).
# No model, no credentials. --assets-root lets prefilter confirm each finding's
# file exists inside the reviewed source tree (and stays inside it).
redteam triage /audit/ENG-ID.jsonl --assets-root ./targets/example-api

# Add the opt-in model stages:
#   --verify  adversarially re-checks each finding (confidence-gated; a refuted
#             finding is dropped, an unconfirmable one is kept as UNVERIFIED —
#             never silently laundered), and
#   --chain   composes the kept findings into validated exploit chains.
redteam triage /audit/ENG-ID.jsonl --assets-root ./targets/example-api \
  --verify --chain --min-confidence 7 --out ./triage-out
```

`--verify` / `--chain` need a reachable model — an `ANTHROPIC_API_KEY` (or
Amazon Bedrock / Google Vertex via `CLAUDE_CODE_USE_BEDROCK` / `_VERTEX`), **or**
a logged-in `claude` CLI. Without any of those the model stages refuse cleanly
(exit non-zero, no artifacts written) and you can still run the deterministic
path. Every model-output path degrades rather than crashing, so a garbage or
truncated reply never breaks the run.

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
├── cli.py              `redteam run` / `triage` / `validate` / `doctor`
├── orchestrator.py     ClaudeSDKClient wiring
├── engagement.py       pydantic schema (single source of truth)
├── preflight.py        readiness checks + model-stage gate
├── auth.py             SSH-signature verification
├── assets.py           read-only mount of source / IaC / specs
├── budget.py           turn / cost / per-target call accounting
├── mcp_external.py     atlassian-only MCP adapter
├── hooks/              scope_guard, audit_writer, redactor, telemetry
├── ledger/             chain + KMS seal + standalone verifier
├── tools/              first-party in-process MCP servers
├── pipeline/           `redteam triage`: prefilter/dedup/enrich + verify/chain
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
The **M3 `redteam triage` findings pipeline** (prefilter / dedup / CWE+CVSS
enrich / opt-in adversarial verify + exploit-chain synthesis → refined SARIF +
markdown + JSON) is implemented and live-verified — see
[Triage](#triage--refine-an-engagements-findings). Still stubbed and clearly
marked: the recon/cloud/network tool bodies, the KMS sealer, and the SSH-sig
parse hook. [CLAUDE.md](CLAUDE.md) lists the suggested next-steps order.
