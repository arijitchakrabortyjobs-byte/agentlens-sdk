"""
AgentLens OpenTelemetry Export
--------------------------------
Emits audit events as OTEL spans for ingestion into Grafana,
Datadog, Azure Monitor, or any OTEL-compatible SIEM.

Falls back gracefully if opentelemetry-sdk is not installed —
AgentLens will continue functioning, just without OTEL export.

Requires (optional):
    pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc

Usage:
    from agentlens.otel import OTELExporter

    exporter = OTELExporter(
        endpoint="http://otel-collector.internal:4317",
        service_name="agentlens-mybank",
    )
    audit_log = AuditLog(entity_name="MyBank", otel_exporter=exporter)

Each audit event becomes an OTEL span with:
  - Span name: agentlens.{event_type}
  - Attributes: all scalar audit fields
  - Status: ERROR for guardrail failures or chain breaks
  - Trace ID: maps to AgentLens trace_id (hex-encoded)
"""

import hashlib
import threading
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .audit_log import AuditEvent

# Graceful import — OTEL is optional
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import SpanKind, StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


class OTELExporter:
    """
    Translates AgentLens AuditEvents into OpenTelemetry spans.

    If opentelemetry-sdk is not installed, all methods are no-ops and
    health_check() reports the missing dependency clearly.
    """

    def __init__(
        self,
        endpoint: str,
        service_name: str = "agentlens",
        use_grpc: bool = True,
        insecure: bool = False,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.endpoint = endpoint
        self.service_name = service_name
        self._tracer: Any = None
        self._provider: Any = None
        self._available = _OTEL_AVAILABLE
        self._init_error: Optional[str] = None
        self._lock = threading.Lock()

        if not _OTEL_AVAILABLE:
            self._init_error = (
                "opentelemetry-sdk not installed. "
                "Run: pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc"
            )
            return

        try:
            resource = Resource.create({
                "service.name": service_name,
                "service.version": "0.2.0",
                "deployment.environment": "production",
            })
            provider = TracerProvider(resource=resource)

            if use_grpc:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                span_exporter = OTLPSpanExporter(
                    endpoint=endpoint,
                    insecure=insecure,
                    headers=headers or {},
                )
            else:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                span_exporter = OTLPSpanExporter(
                    endpoint=endpoint,
                    headers=headers or {},
                )

            provider.add_span_processor(BatchSpanProcessor(span_exporter))
            trace.set_tracer_provider(provider)
            self._provider = provider
            self._tracer = trace.get_tracer(service_name)
        except Exception as e:
            self._init_error = str(e)
            self._available = False

    def _trace_id_from_str(self, s: str) -> int:
        """Convert a string (UUID or arbitrary) to a 128-bit OTEL trace ID int."""
        h = hashlib.md5(s.encode()).hexdigest()
        return int(h, 16)

    def _span_id_from_str(self, s: str) -> int:
        """Convert a string to a 64-bit OTEL span ID int."""
        h = hashlib.md5(s.encode()).hexdigest()[:16]
        return int(h, 16)

    def emit(self, event: "AuditEvent") -> None:
        """
        Emit a single AuditEvent as an OTEL span.
        No-op if opentelemetry-sdk is not available.
        """
        if not self._available or self._tracer is None:
            return

        span_name = f"agentlens.{event.event_type.value}"

        with self._lock:
            with self._tracer.start_as_current_span(
                span_name,
                kind=SpanKind.INTERNAL,
            ) as span:
                # Core identity
                span.set_attribute("agentlens.event_id",    event.event_id)
                span.set_attribute("agentlens.trace_id",    event.trace_id)
                span.set_attribute("agentlens.session_id",  event.session_id)
                span.set_attribute("agentlens.event_type",  event.event_type.value)
                span.set_attribute("agentlens.agent_id",    event.agent_id)
                span.set_attribute("agentlens.agent_version", event.agent_version)
                span.set_attribute("agentlens.risk_tier",   event.risk_tier.value)

                # Model
                if event.model_id:
                    span.set_attribute("agentlens.model_id",      event.model_id)
                    span.set_attribute("agentlens.model_version",  event.model_version or "")

                # Policy
                if event.policy_ref:
                    span.set_attribute("agentlens.policy_ref", event.policy_ref)

                # Guardrail
                span.set_attribute("agentlens.guardrail_triggered", event.guardrail_triggered)
                if event.guardrail_action:
                    span.set_attribute("agentlens.guardrail_action", event.guardrail_action)
                if event.guardrail_rule:
                    span.set_attribute("agentlens.guardrail_rule", event.guardrail_rule)

                # Human oversight
                span.set_attribute("agentlens.human_review_required", event.human_review_required)
                span.set_attribute("agentlens.human_override",        event.human_override)

                # Latency
                if event.latency_ms is not None:
                    span.set_attribute("agentlens.latency_ms", event.latency_ms)

                # Integrity
                span.set_attribute("agentlens.event_hash",     event.event_hash[:16])
                span.set_attribute("agentlens.previous_hash",  event.previous_event_hash[:16])

                # Frameworks
                if event.regulatory_frameworks:
                    span.set_attribute(
                        "agentlens.frameworks",
                        ",".join(event.regulatory_frameworks),
                    )

                # Mark span as error if guardrail blocked or human review required
                if event.guardrail_action == "block":
                    span.set_status(StatusCode.ERROR, f"Guardrail BLOCK: {event.guardrail_rule}")
                elif event.error_code:
                    span.set_status(StatusCode.ERROR, event.error_message or event.error_code)
                else:
                    span.set_status(StatusCode.OK)

    def flush(self, timeout_millis: int = 5000) -> bool:
        """
        Force-flush any spans still sitting in the BatchSpanProcessor buffer.
        Call this before process exit (or after a burst of events you need
        delivered immediately) — otherwise spans can be silently lost if the
        process ends before the processor's periodic export runs.
        Returns True on success (or if there is nothing to flush).
        """
        if not self._available or self._provider is None:
            return True
        return self._provider.force_flush(timeout_millis=timeout_millis)

    def shutdown(self) -> None:
        """Flush pending spans and shut down the tracer provider. Call once at process exit."""
        if not self._available or self._provider is None:
            return
        self._provider.shutdown()

    def health_check(self) -> Dict[str, Any]:
        return {
            "exporter": "OTELExporter",
            "endpoint": self.endpoint,
            "service_name": self.service_name,
            "otel_sdk_available": _OTEL_AVAILABLE,
            "initialised": self._available and self._tracer is not None,
            "error": self._init_error,
        }
