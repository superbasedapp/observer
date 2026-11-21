"""Minimal SuperBased SDK example.

Run a local Observer with [observability] enabled, then:

    pip install -e sdk/python
    python sdk/python/examples/quickstart.py

It emits one trace (an agent span containing an LLM span and a tool span) to
the OTLP receiver at http://127.0.0.1:4318/v1/traces (override with
SUPERBASED_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT). List it with
`observer obs traces` or GET http://127.0.0.1:8081/api/obs/traces.
"""

import uuid

import superbased_sdk as sb


def main() -> None:
    sb.init(session_id="quickstart-1", user="demo", service_name="quickstart")

    with sb.span("agent.run", kind=sb.AGENT):
        with sb.llm_span("chat", model="gpt-4o", provider="openai", prompt="Say hi") as s:
            # ... your real model call goes here; use its real response id ...
            response_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
            sb.set_usage(s, input_tokens=1200, output_tokens=64, response_id=response_id, response="hi")
        with sb.span("web_search", kind=sb.TOOL):
            pass  # ... your tool call ...

    sb.shutdown()  # flush before exit; bounded, never raises
    d = sb.diagnostics()
    if d["failed_exports"]:
        print(f"export failed: {d['last_error']}")
    else:
        print("sent one trace; list it with `observer obs traces`")


if __name__ == "__main__":
    main()
