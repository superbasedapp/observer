"""A LlamaIndex chatbot, traced with superbased.

Two turns through a ``SimpleChatEngine`` (a chat engine with memory and no
retriever), then one turn through a ``FunctionAgent`` with a function tool.
``sb.instrument(["llama-index"])`` records the engine, agent, tool and LLM
spans. Only the LlamaIndex layer is instrumented: turning ``openai`` on as
well would write a second LLM span per call with the same tokens.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import superbased_sdk as sb

SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "llama-index-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

sb.init(service_name=SERVICE, release="examples-1")
print("instrument:", sb.instrument(["llama-index"]), file=sys.stderr)

from llama_index.core.agent.workflow import FunctionAgent  # noqa: E402
from llama_index.core.chat_engine import SimpleChatEngine  # noqa: E402
from llama_index.core.tools import FunctionTool  # noqa: E402
from llama_index.llms.openai import OpenAI  # noqa: E402
from llama_index.core.instrumentation import get_dispatcher  # noqa: E402
from llama_index.core.instrumentation.event_handlers import BaseEventHandler  # noqa: E402
from llama_index.core.instrumentation.events.llm import LLMChatEndEvent  # noqa: E402


def get_order_status(order_id: str) -> str:
    """Look up the shipping status of an order by its id."""
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


# gpt-5-nano is a reasoning model: a reasoning effort and an output cap, no temperature.
llm = OpenAI(model="gpt-5-nano", reasoning_effort="minimal", max_tokens=400)
calls: list[dict] = []


def usage_of(raw) -> None:
    u = getattr(raw, "usage", None) if raw is not None else None
    if u is None and isinstance(raw, dict):
        u = raw.get("usage")
    if u is None:
        return
    get = (lambda k: u.get(k)) if isinstance(u, dict) else (lambda k: getattr(u, k, None))
    calls.append({"kind": "chat", "input": get("prompt_tokens"), "output": get("completion_tokens")})


class UsageRecorder(BaseEventHandler):
    """Keeps what OpenAI reported for each LLM call, for verify.py."""

    @classmethod
    def class_name(cls) -> str:
        return "UsageRecorder"

    def handle(self, event, **kwargs) -> None:
        if isinstance(event, LLMChatEndEvent) and event.response is not None:
            usage_of(event.response.raw)


get_dispatcher().add_event_handler(UsageRecorder())


async def agent_turn(text: str) -> str:
    # streaming=False: the agent's default streamed call asks OpenAI for no
    # usage, so its LLM spans would carry no tokens and stay unpriced.
    agent = FunctionAgent(tools=[FunctionTool.from_defaults(get_order_status)], llm=llm, streaming=False,
                          system_prompt="You are a terse support bot. One sentence answers.")
    resp = await agent.run(user_msg=text)
    return str(resp)


def main() -> int:
    user, session, tenant = "user-ada", f"li-{RUN_ID}", "acme"
    trace_ids = []
    engine = SimpleChatEngine.from_defaults(llm=llm, system_prompt="You are a terse support bot. One sentence answers.")
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant):
        for i, text in enumerate(["Hi, who are you?", "Say that again in five words."], 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                resp = engine.chat(text)
            print(f"turn {i}: {text!r} -> {str(resp)!r}")
        with sb.span("turn-3", kind=sb.AGENT):
            trace_ids.append(sb.get_current_trace_id())
            answer = asyncio.run(agent_turn("Where is my order A-1001?"))
        print(f"turn 3: 'Where is my order A-1001?' -> {answer!r}")
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
