"""A small support chatbot on the OpenAI Python SDK, traced with superbased.

What it shows:
  * ``sb.init()`` then ``sb.instrument(["openai"])``: every OpenAI call becomes
    an LLM span (model, tokens, content) without touching the call sites.
  * Per-request identity (end user, session, customer tenant) with
    ``sb.propagate_attributes``.
  * Three Chat Completions turns, one of them with a function tool call, one
    Responses API call and one streamed Chat Completions call.

Every call uses gpt-5-nano. It is a reasoning model: it takes
``max_completion_tokens`` (Chat Completions) / ``max_output_tokens``
(Responses), not ``max_tokens``, and refuses a non-default ``temperature``.

Run: see README.md. The OpenAI key comes from OPENAI_API_KEY only.
"""

from __future__ import annotations

import json
import os
import sys
import time

from openai import OpenAI

import superbased_sdk as sb

MODEL = "gpt-5-nano"
SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "openai-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

sb.init(service_name=SERVICE, release="examples-1")
status = sb.instrument(["openai"])
print("instrument:", status, file=sys.stderr)

USER = "user-ada"  # the app's end user (an opaque id, not an email address)

if os.environ.get("AI_GATEWAY_URL"):
    # Through the organization's AI gateway: its own key (sbo-vk-...), and the
    # app identity headers its budgets key on. The Python SDK does not send
    # these headers for you. A real app sets X-Superbased-User per request
    # (extra_headers=...); this one-user demo sets it once.
    client = OpenAI(
        base_url=os.environ["AI_GATEWAY_URL"], api_key=os.environ["AI_GATEWAY_KEY"],
        default_headers={"X-Superbased-Service": SERVICE, "X-Superbased-User": USER},
    )
else:
    client = OpenAI()  # OPENAI_API_KEY from the environment

ORDER_TOOL = {
    "type": "function",
    "function": {
        "name": "get_order_status",
        "description": "Look up the shipping status of an order by its id.",
        "parameters": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}},
            "required": ["order_id"],
        },
    },
}


def get_order_status(order_id: str) -> str:
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


calls: list[dict] = []  # what OpenAI reported, for verify.py


def record(kind: str, resp_id: str, usage) -> None:
    if usage is None:
        calls.append({"kind": kind, "id": resp_id})
        return
    if hasattr(usage, "prompt_tokens"):  # Chat Completions
        calls.append({
            "kind": kind, "id": resp_id,
            "input": usage.prompt_tokens, "output": usage.completion_tokens,
            "cached": getattr(usage.prompt_tokens_details, "cached_tokens", 0) or 0,
            "reasoning": getattr(usage.completion_tokens_details, "reasoning_tokens", 0) or 0,
        })
    else:  # Responses
        calls.append({
            "kind": kind, "id": resp_id,
            "input": usage.input_tokens, "output": usage.output_tokens,
            "cached": getattr(usage.input_tokens_details, "cached_tokens", 0) or 0,
            "reasoning": getattr(usage.output_tokens_details, "reasoning_tokens", 0) or 0,
        })


def chat(messages: list, tools: list | None = None):
    kw = {"tools": tools} if tools else {}
    resp = client.chat.completions.create(
        model=MODEL, messages=messages, max_completion_tokens=400,
        reasoning_effort="minimal", **kw,
    )
    record("chat", resp.id, resp.usage)
    return resp.choices[0].message


def main() -> int:
    user, session, tenant = USER, f"chat-{RUN_ID}", "acme"
    trace_ids = []
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant, tags=["example"]):
        messages = [{"role": "system", "content": "You are a terse support bot. Answer in one sentence."}]
        turns = [
            "Hi! What can you help me with?",
            "Where is my order A-1001?",  # the model calls get_order_status
            "Thanks. Say goodbye in five words.",
        ]
        for i, text in enumerate(turns, 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                messages.append({"role": "user", "content": text})
                msg = chat(messages, tools=[ORDER_TOOL])
                if msg.tool_calls:
                    messages.append(msg.model_dump(exclude_none=True))
                    for tc in msg.tool_calls:
                        args = json.loads(tc.function.arguments or "{}")
                        with sb.tool_span("get_order_status", tool_name=tc.function.name,
                                          call_id=tc.id, arguments=args) as ts:
                            result = get_order_status(**args)
                            sb.set_tool_result(ts, result)
                        messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                    msg = chat(messages, tools=[ORDER_TOOL])
                messages.append({"role": "assistant", "content": msg.content or ""})
                print(f"turn {i}: {text!r} -> {msg.content!r}")

        with sb.span("responses-api", kind=sb.AGENT):
            trace_ids.append(sb.get_current_trace_id())
            r = client.responses.create(
                model=MODEL, input="Name one primary colour. One word.",
                max_output_tokens=300, reasoning={"effort": "minimal"},
            )
            record("responses", r.id, r.usage)
            print("responses:", r.output_text)

        with sb.span("streamed", kind=sb.AGENT):
            trace_ids.append(sb.get_current_trace_id())
            stream = client.chat.completions.create(
                model=MODEL, messages=[{"role": "user", "content": "Count to three, digits only."}],
                max_completion_tokens=300, reasoning_effort="minimal", stream=True,
                stream_options={"include_usage": True},
            )
            text, sid, usage = "", "", None
            for chunk in stream:
                sid = chunk.id or sid
                if chunk.usage:
                    usage = chunk.usage
                if chunk.choices and chunk.choices[0].delta.content:
                    text += chunk.choices[0].delta.content
            record("chat-stream", sid, usage)
            print("streamed:", text)

    ok = sb.flush()
    out = {"service": SERVICE, "run_id": RUN_ID, "user": user, "session": session, "tenant": tenant,
           "trace_ids": trace_ids, "calls": calls, "diagnostics": {
               k: v for k, v in sb.diagnostics().items()
               if k in ("destination", "destination_source", "destinations", "failed_exports", "dropped_spans", "warnings")}}
    with open(os.environ.get("RUN_OUT", "run.json"), "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps(out["diagnostics"], default=str), file=sys.stderr)
    sb.shutdown()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
