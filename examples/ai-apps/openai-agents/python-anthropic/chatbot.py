"""An OpenAI Agents SDK chatbot with one function tool, traced with superbased.

``sb.instrument(["openai-agents"])`` turns every agent run, turn, model call
(``generation``) and tool call into a span. While it is on, the Agents SDK's
own trace upload to OpenAI is replaced, so runs are not also sent there.
Three turns share one session, so the agent keeps the conversation.

The model is claude-haiku-5-5 through the Agents SDK's LiteLLM model
(``openai-agents[litellm]``). Effort goes in ``extra_args`` as
``output_config``; no temperature (Haiku 5.5 refuses a non-default one).
"""

from __future__ import annotations

import json
import os
import sys
import time

import superbased_sdk as sb

SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "openai-agents-anthropic-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

sb.init(service_name=SERVICE, release="examples-1")
print("instrument:", sb.instrument(["openai-agents"]), file=sys.stderr)

from agents import Agent, ModelSettings, Runner, SQLiteSession, function_tool  # noqa: E402
from agents.extensions.models.litellm_model import LitellmModel  # noqa: E402


@function_tool
def get_order_status(order_id: str) -> str:
    """Look up the shipping status of an order by its id."""
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


agent = Agent(
    name="support",
    instructions="You are a terse support bot. One sentence answers.",
    model=LitellmModel(model="anthropic/claude-haiku-5-5", api_key=os.environ.get("ANTHROPIC_API_KEY")),
    model_settings=ModelSettings(max_tokens=2000, extra_args={"output_config": {"effort": "low"}}),
    tools=[get_order_status],
)


def main() -> int:
    user, session_id, tenant = "user-ada", f"ag-{RUN_ID}", "acme"
    session = SQLiteSession(session_id)  # in memory
    trace_ids, calls = [], []
    with sb.propagate_attributes(user=user, session_id=session_id, tenant=tenant):
        for i, text in enumerate(["Hi, who are you?", "Where is my order A-1001?", "Thanks, bye."], 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                result = Runner.run_sync(agent, text, session=session)
            for r in result.raw_responses:
                u = r.usage
                calls.append({"kind": "litellm", "id": r.response_id, "input": u.input_tokens,
                              "output": u.output_tokens,
                              "cached": getattr(u.input_tokens_details, "cached_tokens", 0) or 0,
                              "reasoning": getattr(u.output_tokens_details, "reasoning_tokens", 0) or 0})
            print(f"turn {i}: {text!r} -> {result.final_output!r}")
    ok = sb.flush()
    record = {"service": SERVICE, "run_id": RUN_ID, "user": user, "session": session_id, "tenant": tenant,
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
