"""A LlamaIndex chatbot on Claude, traced with superbased.

Two turns through a ``SimpleChatEngine`` (a chat engine with memory and no
retriever), then one turn through a ``FunctionAgent`` with a function tool.
``sb.instrument(["llama-index"])`` records the engine, agent, tool and LLM
spans.

The model is claude-haiku-5-5 through llama-index-llms-anthropic, at low
effort: the LLM has no effort setting, so ``output_config`` goes in
``additional_kwargs``, which it sends with every request.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import superbased_sdk as sb

SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "llama-index-anthropic-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

# The anthropic SDK also traces each API call itself; sb.init() turns that off
# (ANTHROPIC_OPEN_TELEMETRY), so each call is recorded once, by the LlamaIndex
# instrumentor.

sb.init(service_name=SERVICE, release="examples-1")
print("instrument:", sb.instrument(["llama-index"]), file=sys.stderr)

from llama_index.core.agent.workflow import FunctionAgent  # noqa: E402
from llama_index.core.chat_engine import SimpleChatEngine  # noqa: E402
from llama_index.core.instrumentation import get_dispatcher  # noqa: E402
from llama_index.core.instrumentation.event_handlers import BaseEventHandler  # noqa: E402
from llama_index.core.instrumentation.events.llm import LLMChatEndEvent  # noqa: E402
from llama_index.core.tools import FunctionTool  # noqa: E402
from llama_index.llms.anthropic import Anthropic  # noqa: E402


def get_order_status(order_id: str) -> str:
    """Look up the shipping status of an order by its id."""
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


llm = Anthropic(model="claude-haiku-5-5", max_tokens=2000,
                additional_kwargs={"output_config": {"effort": "low"}})
calls: list[dict] = []


def usage_of(raw) -> None:
    u = raw.get("usage") if isinstance(raw, dict) else getattr(raw, "usage", None)
    if u is None:
        return
    get = (lambda k: u.get(k) or 0) if isinstance(u, dict) else (lambda k: getattr(u, k, 0) or 0)
    write, read = get("cache_creation_input_tokens"), get("cache_read_input_tokens")
    # Anthropic's input_tokens leaves the cache out; the whole prompt adds it back.
    calls.append({"kind": "chat", "input": get("input_tokens") + write + read, "output": get("output_tokens"),
                  "cached": read, "cache_write": write})


class UsageRecorder(BaseEventHandler):
    """Keeps what Anthropic reported for each LLM call, for verify.py."""

    @classmethod
    def class_name(cls) -> str:
        return "UsageRecorder"

    def handle(self, event, **kwargs) -> None:
        if isinstance(event, LLMChatEndEvent) and event.response is not None:
            usage_of(event.response.raw)


get_dispatcher().add_event_handler(UsageRecorder())


async def agent_turn(text: str) -> str:
    # streaming=False: a streamed agent call's LLM span carries no tokens.
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
