"""The SAME trace as quickstart.py, but with stock OpenTelemetry and NO
SuperBased SDK. Anything the SDK does, a raw OTel exporter pointed at
Observer does too; the SDK is convenience.

    pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-http
    python sdk/python/examples/raw_otlp.py

The endpoint follows the standard OTel env vars
(OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, or OTEL_EXPORTER_OTLP_ENDPOINT plus
/v1/traces), then SUPERBASED_OTLP_ENDPOINT, then the local node.
"""

import os
import uuid

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def endpoint() -> str:
    explicit = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    if explicit:
        return explicit
    base = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if base:
        return base.rstrip("/") + "/v1/traces"
    return os.environ.get("SUPERBASED_OTLP_ENDPOINT", "http://127.0.0.1:4318/v1/traces")


# Resource tags Observer reads onto the trace. Do NOT set
# sbo.emitted_by=observer: that is Observer's echo-guard marker and the
# resource would be dropped at ingestion. Resource.create also merges
# OTEL_RESOURCE_ATTRIBUTES / OTEL_SERVICE_NAME.
resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "custom-app"),
                            "session.id": "raw-1", "sbo.user": "demo"})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint())))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("raw-example")

with tracer.start_as_current_span("agent.run", attributes={"openinference.span.kind": "AGENT"}):
    with tracer.start_as_current_span(
        "chat",
        attributes={
            "openinference.span.kind": "LLM",
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "openai",
            "gen_ai.system": "openai",  # legacy key, still read by older mappers
            "gen_ai.request.model": "gpt-4o",
            "gen_ai.usage.input_tokens": 1200,
            "gen_ai.usage.output_tokens": 64,
            "gen_ai.response.id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        },
    ):
        pass

provider.shutdown()
print("sent one trace; list it with `observer obs traces`")
