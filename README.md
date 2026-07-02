# redteam

Modular security testing harness on the Claude Agent SDK. **It's functional,
not a blueprint** — the security / audit / policy spine is real and enforced,
the container has run a real autonomous engagement end-to-end, and the recon,
web, network, whitebox, report, and triage flows all work. What's left is
scoped and tracked: the AWS `cloud` pack and a handful of tools are still stubs,
plus a set of hardening items — see
[docs/REMAINING-WORK.md](docs/REMAINING-WORK.md).

The complete design doc is in [docs/PLAN.md](docs/PLAN.md); orientation and the
**hard constraints** (for any continuing session, human or AI) are in
[CLAUDE.md](CLAUDE.md). **New contributor?** Read those two plus
[docs/REMAINING-WORK.md](docs/REMAINING-WORK.md), then see
[Continuing this work](#continuing-this-work--contributing).

## What it is

A controlled, repeatable harness for **authorized** red-team engagements
against systems the operating org owns. The operator declares scope and
an objective in a signed YAML; an agent runs unattended inside an
ephemeral container, with every tool call gated by policy and recorded
in a tamper-evident hash-chained ledger.

The four properties the design protects:

- **Observability** — the container ships Claude Code OTel metrics to an
  auto-provisioned Grafana / Prometheus / Tempo dev stack (or a central one);
  the app's own tool-span events are the next step (RT-22).
- **Auditability** — AWS KMS-sealed, hash-chained JSONL ledger; standalone
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

Additional opt-in stages / flags:

- `--semantic-dedup` — a model pass that merges same-root-cause findings the
  deterministic `(file, vuln_class)` dedup misses. Conservative: same-file only,
  and every merge is recorded in the dropped list (auditable, never silently
  deleted).
- `--security-requirements CR:H,IR:H,AR:M` — engagement-wide CVSS **environmental**
  Security Requirements, which feed an **offensive-priority** score (P1–P4)
  blending environmental CVSS + exploitability + verify verdict + exploit-chain
  membership (surfaced in the SARIF/markdown/JSON).
- `--jira-project SEC` — also emit `<ledger>.jira.json`, an idempotent Jira
  upsert bundle with a deterministic external key so re-runs update tickets in
  place (the agent/operator applies it via the Atlassian MCP).
- `--verify-model` / `--chain-model` / `--dedup-model` — route each model stage
  to a different model id (falling back to `--model`).

`--verify` / `--chain` / `--semantic-dedup` need a reachable model — an
`ANTHROPIC_API_KEY` (or Amazon Bedrock / Google Vertex via
`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX`), **or** a logged-in `claude` CLI. Without
any of those the model stages refuse cleanly (exit non-zero, no artifacts
written) and you can still run the deterministic path. Every model-output path
degrades rather than crashing, so a garbage or truncated reply never breaks the
run.

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
├── pipeline/           `redteam triage`: prefilter/dedup/enrich (base+env CVSS) +
│                       verify/chain/semantic-dedup/prioritise + emit
├── subagents/          markdown system prompts
├── jira.py             deterministic Atlassian/Jira idempotency logic
└── runtime/            Dockerfile, docker-compose, entrypoint, netpolicy, otel/

engagements/            example.yaml + authorized_signers
targets/                operator clones target repos here via `gh`
tests/                  contract + hardening suite (391 tests)
docs/PLAN.md            full design doc
docs/REMAINING-WORK.md  consolidated open-items backlog (start here to continue)
docs/REVIEW.md          dated narrative log of every fix batch
docs/review-findings.json  structured findings + fix_batches (source of truth)
CLAUDE.md               orientation + hard constraints for continuing sessions
```

## Status

**Functional, built cage-first — no longer a blueprint.**

Real, tested, and *enforced* — the security / audit spine: the pydantic schema,
scope guard, hash-chained ledger with **AWS KMS seal**, SSH-signature gating on
`redteam run`, the egress netpolicy renderer (RT-23), and the atomic SARIF
writer (RT-21). The runtime image ships Node + the pinned `claude` CLI (the
Agent SDK's transport), so the container runs a contained engagement end-to-end
(`redteam doctor --probe` confirms readiness;
`engagements/whitebox-first.example.yaml` is the first contained run). A **real
autonomous engagement has run** (on the host `claude` CLI): the agent reviewed a
planted-vulnerable backend, the cage denied/allowed tools live, and 6 correct
findings sealed into the ledger and passed `redteam-verify`.

Working tool packs: **recon** (DNS + `gh_*` GitHub search), **web** (HTTP with
method-allowlist + no-redirect), **network** (async TCP connect / port scan),
**whitebox** (repo read/grep + real **semgrep / tfsec / checkov**), **report**
(SARIF + idempotent Jira upsert). The **M3 `redteam triage` pipeline** —
prefilter / dedup / CWE + CVSS (base **and** environmental) enrich / opt-in
adversarial verify + exploit-chain synthesis + semantic dedup + offensive
priority + per-stage model routing → refined SARIF + markdown + JSON — is
implemented; its core is live-verified (the v-next stages — semantic dedup,
environmental scoring, model routing — are mock/contract-tested). See
[Triage](#triage--refine-an-engagements-findings).

Still stubbed or pending (all tracked in
[docs/REMAINING-WORK.md](docs/REMAINING-WORK.md)):

- the **`cloud` pack** (AWS `list_buckets` / `describe_iam`) — the only
  fully-stubbed pack;
- individual tools: `whois`, `cert_transparency` (recon); `sbom_query`,
  `openapi_diff`, `dependency_audit` (whitebox);
- the app's own OTel tracer + tool-span events (RT-22);
- the fully-hardened *container* autonomous run (secret→env, asset-mount,
  backend-egress wiring — the proven autonomous run used the host CLI);
- open hardening findings (RT-16/17/18/20/24/25/26, …) and the "not yet
  exercised against live AWS / Jira / Grafana" verification gaps.

## Continuing this work / contributing

Built to be picked up by anyone — a later session or a new contributor.

- **[docs/REMAINING-WORK.md](docs/REMAINING-WORK.md)** — the consolidated
  backlog: what's open, why, where to start, and a suggested order.
- **[docs/review-findings.json](docs/review-findings.json)** — the structured
  source of truth (every finding + the `fix_batches` history, each with a
  per-batch `residual`).
- **[CLAUDE.md](CLAUDE.md)** — orientation + the **hard constraints** that must
  not be relaxed without a deliberate decision (see [Design constraints](#design-constraints-binding-for-v1)).

The working cadence — please keep it: **TDD** (write the failing test first),
then an **adversarial review pass** before merging, then update the docs
(`review-findings.json` + `REVIEW.md`) and commit. Don't broaden the scope-guard
defaults or tool allowlists "to make things work" — the defence-in-depth model
(**the hook is the gate, the tool is the lock**) is load-bearing.

```bash
pip install -e ".[dev]"
pytest                       # contract + hardening suite (391 passing)
ruff check redteam tests
```
