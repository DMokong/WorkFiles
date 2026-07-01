"""redteam.pipeline — the M3 `redteam triage` findings pipeline.

Turns raw ``finding.recorded`` ledger entries into trustworthy findings:
deduplicated, CWE/CVSS-enriched, optionally adversarially verified and composed
into exploit chains, then emitted as a refined SARIF + markdown report.

The deterministic stages (prefilter, dedup, enrich, emit) need no model or
credentials; the model-driven stages (verify, chain) are opt-in and reuse the
engagement's backend. Every stage is fail-closed: a malformed finding or garbage
model output is dropped/degraded, never crashes the pipeline.
"""

from __future__ import annotations
