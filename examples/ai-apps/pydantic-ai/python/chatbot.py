"""A Pydantic AI chatbot with one tool, traced with superbased.

``sb.instrument(["pydantic-ai"])`` turns on Pydantic AI's own OpenTelemetry
spans (``Agent.instrument_all``) with the SDK's provider and adds the
OpenInference attributes superbased reads. Three turns pass the message
history along, so the agent keeps the conversation.
"""

from __future__ import annotations

import json
import os
import sys
import time

import superbased_sdk as sb

SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "pydantic-ai-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

sb.init(service_name=SERVICE, release="examples-1")
print("instrument:", sb.instrument(["pydantic-ai"]), file=sys.stderr)

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.messages import ModelResponse  # noqa: E402

# gpt-5-nano is a reasoning model: a reasoning effort and a token cap, no temperature.
agent = Agent(
    "openai:gpt-5-nano",
    instructions="You are a terse support bot. One sentence answers.",
    model_settings={"openai_reasoning_effort": "minimal", "max_tokens": 400},
)


@agent.tool_plain
def get_order_status(order_id: str) -> str:
    """Look up the shipping status of an order by its id."""
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


def main() -> int:
    user, session, tenant = "user-ada", f"pa-{RUN_ID}", "acme"
    trace_ids, calls, history = [], [], []
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant):
        for i, text in enumerate(["Hi, who are you?", "Where is my order A-1001?", "Thanks, bye."], 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                result = agent.run_sync(text, message_history=history)
            for m in result.new_messages():
                if isinstance(m, ModelResponse):
                    calls.append({"kind": "chat", "id": m.provider_response_id,
                                  "input": m.usage.input_tokens, "output": m.usage.output_tokens,
                                  "cached": m.usage.cache_read_tokens})
            history = result.all_messages()
            print(f"turn {i}: {text!r} -> {result.output!r}")
    ok = sb.flush()
    record = {"service": SERVICE, "run_id": RUN_ID, "user": user, "session": session, "tenant": tenant,
              "trace_ids": trace_ids, "calls": calls,
              "diagnostics": {k: v for k, v in sb.diagnostics().items()
                              if k in ("destination", "destinations", "failed_exports", "dropped_spans")}}
    with open(os.environ.get("RUN_OUT", "run.json"), "w") as f:
        json.dump(record, f, indent=2, default=str)
    print(json.dumps(record["diagnostics"], default=str), file=sys.stderr)
    sb.shutdown()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
