"""Telemetry - a real OpenTelemetry TracerProvider + the harness's own spans.

The Claude Code CLI (the SDK transport) emits its own OTel metrics/logs via env
config (see runtime/docker-compose). This module is the *redteam app's* side: it
configures a TracerProvider with an OTLP span exporter (``setup_tracing``) and
emits a span per significant action — ``tool.invoked`` / ``tool.denied`` (from
the scope-guard hook) and ``finding.recorded`` (from the report pack) — so the
harness's decisions show up in Tempo, not just the model's token metrics (RT-22).

Everything degrades: no OTel SDK, or no configured provider/endpoint, means the
spans are no-ops, never a crash.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode

    _HAS_OTEL = True
except ImportError:  # pragma: no cover - opentelemetry-api is a declared dep
    _HAS_OTEL = False

try:
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor

    _HAS_OTEL_SDK = True
except ImportError:  # pragma: no cover - opentelemetry-sdk is a declared dep
    _HAS_OTEL_SDK = False


def build_tracer_provider(
    service_name: str, endpoint: str | None = None, span_exporter: Any | None = None
) -> Any | None:
    """Build a TracerProvider exporting to ``endpoint`` (OTLP/gRPC) or to an
    injected ``span_exporter`` (tests). Returns None when the SDK is absent or
    there is nowhere to export — the caller then runs with no-op spans."""
    if not _HAS_OTEL_SDK:
        return None
    if span_exporter is None and not endpoint:
        return None
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    if span_exporter is not None:
        provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    else:
        # Import lazily: the OTLP exporter pulls grpc, unwanted unless we export.
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        # In-cluster hop to the collector is plaintext (like the CLI's exporter);
        # the collector->backend TLS is gated separately in collector.yaml.
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
        )
    return provider


_TRACING_INITIALIZED = False


def setup_tracing(service_name: str, endpoint: str | None = None) -> bool:
    """Install a global TracerProvider once (idempotent). Returns True if a real
    provider was set — so the app's spans (via the global tracer) actually
    record. A no-op (no SDK / no endpoint) returns False and leaves spans no-op."""
    global _TRACING_INITIALIZED
    if _TRACING_INITIALIZED or not _HAS_OTEL:
        return _TRACING_INITIALIZED
    provider = build_tracer_provider(service_name, endpoint=endpoint)
    if provider is None:
        return False
    trace.set_tracer_provider(provider)
    _TRACING_INITIALIZED = True
    return True


class Telemetry:
    """Thin wrapper so callers don't need to know whether OTel is wired.

    Each ``event_*`` produces a standalone span (a leaf); inside a ``tool_span``
    context those become children of the wrapping span. ``tracer_provider`` lets
    a test bind a specific in-memory provider without touching global state.
    """

    def __init__(self, service_name: str = "redteam", tracer_provider: Any | None = None):
        self.service_name = service_name
        if not _HAS_OTEL:
            self._tracer = None
        elif tracer_provider is not None:
            self._tracer = tracer_provider.get_tracer(service_name)
        else:
            # Global tracer: a ProxyTracer that resolves to whatever provider
            # setup_tracing() installs (called before any tool call).
            self._tracer = trace.get_tracer(service_name)

    @contextmanager
    def tool_span(self, tool_name: str, attrs: dict[str, Any]) -> Iterator[Any]:
        if self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(f"tool:{tool_name}") as span:
            _set_attrs(span, {f"redteam.tool.{k}": v for k, v in attrs.items()})
            try:
                yield span
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise

    def _emit(self, name: str, attrs: dict[str, Any]) -> None:
        """Emit a single leaf span (parented to the current span if any)."""
        if self._tracer is None:
            return
        span = self._tracer.start_span(name)
        _set_attrs(span, attrs)
        span.end()

    def event_tool_invoked(self, tool_name: str, target: str | None = None) -> None:
        self._emit(
            "tool.invoked",
            {"redteam.tool.name": tool_name, "redteam.tool.target": target or ""},
        )

    def event_tool_denied(self, tool_name: str, reason: str) -> None:
        self._emit(
            "tool.denied",
            {"redteam.tool.name": tool_name, "redteam.tool.deny_reason": reason},
        )

    def event_finding(self, severity: str, title: str) -> None:
        self._emit(
            "finding.recorded",
            {"redteam.finding.severity": severity, "redteam.finding.title": title},
        )


def _set_attrs(span: Any, attrs: dict[str, Any]) -> None:
    for k, v in attrs.items():
        if isinstance(v, (str, int, float, bool)):
            span.set_attribute(k, v)
