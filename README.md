# harness

Modular security testing harness on the Claude Agent SDK.

> Working name. Pick the real one (`redteam`, `aegis`, `recon`, internal
> codename, etc.) before Phase 1 ships - it is a single rename across this
> repo. There is **no relation to Squid (the proxy)**.

## What it is

A controlled, repeatable harness for authorized red-team engagements
against systems your org owns. The operator declares a scope and an
objective in YAML; the agent runs unattended inside an ephemeral
container, with every tool call gated by policy and recorded in a
tamper-evident ledger.

The four properties the design protects:

- **Observability** - live OTel + structured tool events.
- **Auditability** - signed, hash-chained JSONL ledger; standalone verifier.
- **Customisability** - per-engagement scope, tools, egress, subagents.
- **Autonomy** - long unattended runs with budget/turn caps.

## Quickstart

```bash
pip install -e ".[dev]"
harness run engagements/example.yaml
harness-verify /audit/ENG-2026-04-001.jsonl /audit/ENG-2026-04-001.seal
```

## Repo layout

See the plan file for the full layout and architecture decisions.

## Third-party MCP policy

By design, the harness has **no general dependency on third-party MCP
platforms**. The schema only accepts `github` and `atlassian` under
`external_mcp:`; adding a third provider requires a code change.
Everything else is bespoke and lives under `harness/tools/`.

## Status

Greenfield. Phase 1-3 scaffolds are in place; tool packs and runtime
hardening are wired but expect iteration.
