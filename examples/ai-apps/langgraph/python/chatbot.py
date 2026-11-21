"""A LangGraph ReAct chatbot with one tool, traced with superbased.

``sb.instrument(["langgraph"])`` (the LangChain instrumentor; LangGraph runs
are LangChain runs) turns every graph, node, tool and model call into a span.
Three turns share one checkpointer thread, so the agent keeps the conversation.
Each turn is its own trace. The model is gpt-5-nano through langchain-openai.
"""

from __future__ import annotations

import json
import os
import sys
import time

import superbased_sdk as sb

SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "langgraph-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

sb.init(service_name=SERVICE, release="examples-1")
print("instrument:", sb.instrument(["langgraph"]), file=sys.stderr)

from langchain_core.tools import tool  # noqa: E402
from langchain_openai import ChatOpenAI  # noqa: E402
from langgraph.checkpoint.memory import InMemorySaver  # noqa: E402

try:  # LangChain 1.x
    from langchain.agents import create_agent as _create

    def make_agent(model, tools, checkpointer):
        return _create(model, tools=tools, checkpointer=checkpointer,
                       system_prompt="You are a terse support bot. One sentence answers.")
except ImportError:  # LangGraph's prebuilt agent
    from langgraph.prebuilt import create_react_agent as _create

    def make_agent(model, tools, checkpointer):
        return _create(model, tools=tools, checkpointer=checkpointer,
                       prompt="You are a terse support bot. One sentence answers.")


@tool
def get_order_status(order_id: str) -> str:
    """Look up the shipping status of an order by its id."""
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


# gpt-5-nano is a reasoning model: no temperature, and a completion-token cap.
model = ChatOpenAI(model="gpt-5-nano", reasoning_effort="minimal", max_completion_tokens=400)
agent = make_agent(model, [get_order_status], InMemorySaver())


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
                    calls.append({"kind": "chat", "input": um["input_tokens"], "output": um["output_tokens"],
                                  "cached": (um.get("input_token_details") or {}).get("cache_read", 0),
                                  "reasoning": (um.get("output_token_details") or {}).get("reasoning", 0)})
            seen = len(msgs)
            print(f"turn {i}: {text!r} -> {msgs[-1].content!r}")
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
