"""A LangGraph agent with one tool on Claude, traced with superbased.

``sb.instrument(["langgraph"])`` (the LangChain instrumentor; LangGraph runs
are LangChain runs) turns every graph, node, tool and model call into a span.
Three turns share one checkpointer thread, so the agent keeps the
conversation. Each turn is its own trace.

The model is claude-haiku-5-5 through langchain-anthropic, at low effort
(``ChatAnthropic(effort="low")``, sent as ``output_config.effort``). No
temperature is set: Haiku 5.5 refuses a non-default one. The system prompt is
a long policy marked with ``cache_control``, so the first model call writes
Anthropic's prompt cache and the later ones read it.
"""

from __future__ import annotations

import json
import os
import sys
import time

import superbased_sdk as sb

SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "langgraph-anthropic-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

# The anthropic SDK (1.14+) also traces each API call itself; sb.init() turns
# that off (ANTHROPIC_OPEN_TELEMETRY), so each call is recorded once, by the
# LangChain instrumentor.

sb.init(service_name=SERVICE, release="examples-1")
print("instrument:", sb.instrument(["langgraph"]), file=sys.stderr)

from langchain_anthropic import ChatAnthropic  # noqa: E402
from langchain_core.messages import SystemMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402
from langgraph.prebuilt import create_react_agent  # noqa: E402

# Long enough to cache on Haiku 5.5; the run id makes each run write its own entry.
POLICY = f"Policy set {RUN_ID}.\n" + "\n".join(
    f"Policy {i}: Orders placed on business day {i} ship within {i % 3 + 1} business days; "
    f"returns are accepted within 30 days with the original receipt."
    for i in range(1, 120)
)
SYSTEM = SystemMessage(content=[{
    "type": "text", "text": "You are a terse support bot. One sentence answers.\n\n" + POLICY,
    "cache_control": {"type": "ephemeral"},
}])


@tool
def get_order_status(order_id: str) -> str:
    """Look up the shipping status of an order by its id."""
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


model = ChatAnthropic(model="claude-haiku-5-5", effort="low", max_tokens=2000)
agent = create_react_agent(model, tools=[get_order_status], checkpointer=InMemorySaver(), prompt=SYSTEM)


def main() -> int:
    user, session, tenant = "user-ada", f"lg-{RUN_ID}", "acme"
    trace_ids, calls = [], []
    cfg = {"configurable": {"thread_id": session}}
    seen = 0
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant):
        for i, text in enumerate(["Hi, who are you?", "Where is my order A-1001?", "Thanks, bye."], 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                state = agent.invoke({"messages": [{"role": "user", "content": text}]}, cfg)
            msgs = state["messages"]
            for m in msgs[seen:]:
                um = getattr(m, "usage_metadata", None)
                if um:
                    # LangChain's input_tokens is the whole prompt (Anthropic's
                    # input_tokens plus the cache read and cache write). With
                    # Anthropic's per-TTL split, the cache write is reported in
                    # ephemeral_5m/1h_input_tokens and cache_creation reads 0.
                    d = um.get("input_token_details") or {}
                    write = sum(d.get(k, 0) or 0 for k in
                                ("cache_creation", "ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"))
                    calls.append({"kind": "chat", "input": um["input_tokens"], "output": um["output_tokens"],
                                  "cached": d.get("cache_read", 0) or 0, "cache_write": write})
            seen = len(msgs)
            print(f"turn {i}: {text!r} -> {msgs[-1].text!r}")
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
