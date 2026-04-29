"""Telemetry hook - emit OpenTelemetry spans + structured events for tool calls.

The SDK's built-in OTel instrumentation already covers model spans and
token metrics. This hook only adds tool-level enrichment.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, Status, StatusCode

    _HAS_OTEL = True
except ImportError:  # pragma: no cover
    _HAS_OTEL = False
    Span = object  # type: ignore[assignment,misc]


class Telemetry:
    """Thin wrapper so callers don't need to know whether OTel is wired."""

    def __init__(self, service_name: str = "redteam"):
        self.service_name = service_name
        self._tracer = trace.get_tracer(service_name) if _HAS_OTEL else None

    @contextmanager
    def tool_span(self, tool_name: str, attrs: dict[str, Any]) -> Iterator[Any]:
        if self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(f"tool:{tool_name}") as span:
            for k, v in attrs.items():
                if isinstance(v, (str, int, float, bool)):
                    span.set_attribute(f"redteam.tool.{k}", v)
            try:
                yield span
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise

    def event_tool_denied(self, tool_name: str, reason: str) -> None:
        if self._tracer is None:
            return
        span = trace.get_current_span()
        span.add_event(
            "tool.denied",
            attributes={"redteam.tool.name": tool_name, "redteam.tool.deny_reason": reason},
        )

    def event_finding(self, severity: str, title: str) -> None:
        if self._tracer is None:
            return
        span = trace.get_current_span()
        span.add_event(
            "finding.recorded",
            attributes={"redteam.finding.severity": severity, "redteam.finding.title": title},
        )
