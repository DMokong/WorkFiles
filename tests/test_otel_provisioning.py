"""OTel/Grafana provisioning contract (build-next #7).

`docker compose up` (dev profile) must light up Grafana with populated panels
with no manual import: a provisioned Prometheus + Tempo datasource, a dashboard
provider that auto-loads the redteam dashboard, a collector that routes metrics
to Prometheus (not Tempo), and the Claude Code telemetry env vars set on the
redteam service so the spawned `claude` CLI actually emits `claude_code.*`.

These are structure contracts over the shipped config files (no containers run).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

RUNTIME = Path(__file__).resolve().parent.parent / "redteam" / "runtime"
OTEL = RUNTIME / "otel"


def _yaml(p: Path):
    return yaml.safe_load(p.read_text())


def _compose():
    return _yaml(RUNTIME / "docker-compose.yml")


def _env_map(service: dict) -> dict:
    env = service.get("environment", {})
    if isinstance(env, list):  # "KEY=value" list form
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return dict(env)


# ---- Claude Code telemetry env on the redteam service -----------------------


def test_redteam_service_sets_claude_code_telemetry_env() -> None:
    env = _env_map(_compose()["services"]["redteam"])
    assert env.get("CLAUDE_CODE_ENABLE_TELEMETRY") in ("1", 1)
    assert env.get("OTEL_METRICS_EXPORTER") == "otlp"
    assert env.get("OTEL_LOGS_EXPORTER") == "otlp"
    assert env.get("OTEL_EXPORTER_OTLP_PROTOCOL") == "grpc"
    # gRPC OTLP goes to the collector on 4317.
    assert "otel-collector:4317" in env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")


# ---- collector routes metrics to Prometheus (not Tempo) ---------------------


def test_collector_exports_metrics_to_prometheus() -> None:
    c = _yaml(OTEL / "collector.yaml")
    assert "prometheus" in c["exporters"], "a prometheus exporter must be defined"
    metrics_exporters = c["service"]["pipelines"]["metrics"]["exporters"]
    assert "prometheus" in metrics_exporters
    # Metrics must NOT be shipped to the traces backend.
    assert "otlp" not in metrics_exporters, "metrics must not go to tempo (traces-only)"
    # Traces still go to tempo via otlp.
    assert "otlp" in c["service"]["pipelines"]["traces"]["exporters"]


# ---- Grafana datasource provisioning ----------------------------------------


def test_datasources_provision_prometheus_and_tempo() -> None:
    ds = _yaml(OTEL / "grafana" / "provisioning" / "datasources" / "datasources.yaml")
    types = {d["type"]: d for d in ds["datasources"]}
    assert "prometheus" in types and "tempo" in types
    assert "prometheus" in types["prometheus"]["url"]
    assert "tempo" in types["tempo"]["url"]


def test_dashboard_provider_points_at_mounted_dir() -> None:
    prov = _yaml(OTEL / "grafana" / "provisioning" / "dashboards" / "dashboards.yaml")
    paths = [p["options"]["path"] for p in prov["providers"]]
    assert "/var/lib/grafana/dashboards" in paths


# ---- the dashboard actually queries Claude Code metrics ---------------------


def test_dashboard_queries_claude_code_metrics() -> None:
    dash = json.loads((OTEL / "grafana" / "dashboards" / "redteam-engagement.json").read_text())
    assert dash.get("title") and dash.get("panels")
    exprs = [
        t.get("expr", "")
        for panel in dash["panels"]
        for t in panel.get("targets", [])
    ]
    joined = " ".join(exprs)
    # The panels populate from real Claude Code OTLP metrics (Prometheus-mangled).
    assert "claude_code_" in joined
    assert any("token_usage" in e for e in exprs)


def test_metric_names_match_collector_suffix_setting() -> None:
    # Names are predictable (plain dots->underscores) ONLY because the exporter
    # disables unit/_total suffixing. Lock the two together so flipping one
    # without the other (which silently breaks the panels) fails the suite.
    c = _yaml(OTEL / "collector.yaml")
    assert c["exporters"]["prometheus"].get("add_metric_suffixes") is False
    dash = json.loads((OTEL / "grafana" / "dashboards" / "redteam-engagement.json").read_text())
    exprs = " ".join(
        t.get("expr", "") for p in dash["panels"] for t in p.get("targets", [])
    ).lower()
    # No suffixed forms (would appear iff add_metric_suffixes were true).
    assert "token_usage_tokens" not in exprs and "cost_usage_usd" not in exprs


# ---- compose wires the dev stack so `up` populates panels -------------------


def test_compose_wires_grafana_provisioning_and_prometheus() -> None:
    services = _compose()["services"]
    assert "prometheus" in services, "a prometheus service must scrape the collector"

    grafana_vols = " ".join(services["grafana"].get("volumes", []))
    assert "provisioning" in grafana_vols
    assert "/var/lib/grafana/dashboards" in grafana_vols

    # Tempo must have its config mounted (else it won't start).
    tempo_vols = " ".join(services["tempo"].get("volumes", []))
    assert "tempo.yaml" in tempo_vols


def test_tempo_and_prometheus_configs_are_valid() -> None:
    assert _yaml(OTEL / "tempo.yaml")  # non-empty, parses
    prom = _yaml(OTEL / "prometheus.yml")
    jobs = [s["job_name"] for s in prom["scrape_configs"]]
    assert any("collector" in j or "otel" in j for j in jobs)
