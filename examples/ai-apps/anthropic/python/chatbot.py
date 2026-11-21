"""A small support chatbot on the Anthropic Python SDK, traced with superbased.

What it shows:
  * ``sb.init()`` then ``sb.instrument(["anthropic"])``: every Messages API
    call becomes an LLM span (model, tokens, content) without touching the
    call sites.
  * Per-request identity (end user, session, customer tenant) with
    ``sb.propagate_attributes``.
  * Three turns, one of them with a tool call (``tool_use`` /
    ``tool_result`` blocks), one streamed call, and a prompt-caching pair:
    the same long system prompt sent twice with ``cache_control``, so the
    first call writes the cache and the second reads it.

Every call uses claude-haiku-5-5 at low effort (``output_config={"effort":
"low"}``). Haiku 5.5 runs adaptive thinking by default; it refuses a
non-default ``temperature``/``top_p``/``top_k`` and a
``thinking={"type": "enabled", "budget_tokens": ...}`` budget, so neither is
sent. One call asks for summarized thinking (``display: "summarized"``) so
thinking text is present to be captured.

Anthropic reports ``input_tokens`` NET of the cache:
input_tokens + cache_creation_input_tokens + cache_read_input_tokens is the
whole prompt. run.json records that GROSS figure, which is what superbased
stores as a span's input tokens.

Run: see README.md. The key comes from ANTHROPIC_API_KEY only.
"""

from __future__ import annotations

import json
import os
import sys
import time

import anthropic

import superbased_sdk as sb

MODEL = "claude-haiku-5-5"
EFFORT = {"effort": "low"}
SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "anthropic-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))

sb.init(service_name=SERVICE, release="examples-1")
status = sb.instrument(["anthropic"])
print("instrument:", status, file=sys.stderr)

USER = "user-ada"  # the app's end user (an opaque id, not an email address)

if os.environ.get("AI_GATEWAY_URL"):
    # Through the organization's AI gateway: its own key (sbo-vk-...), sent
    # as a bearer token, and the app identity headers its budgets key on. The
    # base URL is the gateway root: the SDK adds /v1/messages itself.
    client = anthropic.Anthropic(
        base_url=os.environ["AI_GATEWAY_URL"], api_key=None,
        auth_token=os.environ["AI_GATEWAY_KEY"],
        default_headers={"X-Superbased-Service": SERVICE, "X-Superbased-User": USER},
    )
else:
    client = anthropic.Anthropic()  # ANTHROPIC_API_KEY from the environment

ORDER_TOOL = {
    "name": "get_order_status",
    "description": "Look up the shipping status of an order by its id.",
    "input_schema": {
        "type": "object",
        "properties": {"order_id": {"type": "string"}},
        "required": ["order_id"],
    },
}

SYSTEM = "You are a terse support bot. Answer in one sentence."

# A policy long enough to be cached (well above Haiku 5.5's minimum cacheable
# prefix). Byte-identical on both calls, so the second call reads the cache.
# The run id at its top makes each run write its own cache entry first.
POLICY = f"Policy set {RUN_ID}.\n" + "\n".join(
    f"Policy {i}: Orders placed on business day {i} ship within {i % 3 + 1} business days; "
    f"returns for those orders are accepted within 30 days with the original receipt, "
    f"refunds go to the original payment method within {i % 5 + 3} days, and store credit "
    f"is offered when the receipt is missing. Gift orders follow the same rule."
    for i in range(1, 90)
)


def get_order_status(order_id: str) -> str:
    return json.dumps({"order_id": order_id, "status": "shipped", "eta_days": 2})


calls: list[dict] = []  # what Anthropic reported, for verify.py


def record(kind: str, msg) -> None:
    u = msg.usage
    write = u.cache_creation_input_tokens or 0
    read = u.cache_read_input_tokens or 0
    calls.append({
        "kind": kind, "id": msg.id, "model": msg.model,
        "input": u.input_tokens + write + read,  # gross: the whole prompt
        "input_net": u.input_tokens, "cache_write": write, "cached": read,
        "output": u.output_tokens,  # includes thinking
        "thinking_blocks": sum(1 for b in msg.content if b.type == "thinking"),
        "thinking_chars": sum(len(getattr(b, "thinking", "") or "") for b in msg.content if b.type == "thinking"),
        "usage": u.model_dump(exclude_none=True),
    })


def text_of(msg) -> str:
    return "".join(b.text for b in msg.content if b.type == "text")


def ask(messages: list, **kw):
    msg = client.messages.create(model=MODEL, max_tokens=2000, output_config=EFFORT,
                                 messages=messages, **kw)
    record("messages", msg)
    return msg


def main() -> int:
    user, session, tenant = USER, f"chat-{RUN_ID}", "acme"
    trace_ids = []
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant, tags=["example"]):
        messages: list = []
        turns = [
            "Hi! What can you help me with?",
            "Where is my order A-1001?",  # the model calls get_order_status
            "Thanks. Say goodbye in five words.",
        ]
        for i, text in enumerate(turns, 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                messages.append({"role": "user", "content": text})
                msg = ask(messages, system=SYSTEM, tools=[ORDER_TOOL])
                while msg.stop_reason == "tool_use":
                    # Pass the whole assistant turn back unchanged (thinking
                    # blocks included), then every tool_result in one message.
                    messages.append({"role": "assistant", "content": msg.content})
                    results = []
                    for b in msg.content:
                        if b.type != "tool_use":
                            continue
                        with sb.tool_span("get_order_status", tool_name=b.name,
                                          call_id=b.id, arguments=b.input) as ts:
                            result = get_order_status(**b.input)
                            sb.set_tool_result(ts, result)
                        results.append({"type": "tool_result", "tool_use_id": b.id, "content": result})
                    messages.append({"role": "user", "content": results})
                    msg = ask(messages, system=SYSTEM, tools=[ORDER_TOOL])
                messages.append({"role": "assistant", "content": msg.content})
                print(f"turn {i}: {text!r} -> {text_of(msg)!r}")

        with sb.span("thinking", kind=sb.AGENT):
            # Summarized thinking, so the thinking blocks carry text.
            trace_ids.append(sb.get_current_trace_id())
            msg = client.messages.create(
                model=MODEL, max_tokens=4000, output_config=EFFORT,
                thinking={"type": "adaptive", "display": "summarized"},
                messages=[{"role": "user", "content":
                           "Alice is older than Bob. Carol is younger than Dan but older than Alice. "
                           "Erin is older than Dan. Who is the second oldest? Check carefully, then "
                           "answer with one name."}],
            )
            record("thinking", msg)
            print("thinking:", text_of(msg), f"({calls[-1]['thinking_blocks']} thinking block(s))")

        with sb.span("streamed", kind=sb.AGENT):
            trace_ids.append(sb.get_current_trace_id())
            text = ""
            with client.messages.stream(
                model=MODEL, max_tokens=2000, output_config=EFFORT,
                messages=[{"role": "user", "content": "Count to three, digits only."}],
            ) as stream:
                for chunk in stream.text_stream:
                    text += chunk
                final = stream.get_final_message()
            record("stream", final)
            print("streamed:", text)

        for n in (1, 2):
            with sb.span(f"cached-{n}", kind=sb.AGENT):
                trace_ids.append(sb.get_current_trace_id())
                msg = client.messages.create(
                    model=MODEL, max_tokens=1000, output_config=EFFORT,
                    system=[{"type": "text", "text": SYSTEM + "\n\n" + POLICY,
                             "cache_control": {"type": "ephemeral"}}],
                    messages=[{"role": "user", "content":
                               f"Question {n}: how long do refunds take for orders from business day {n + 10}?"}],
                )
                record(f"cached-{n}", msg)
                c = calls[-1]
                print(f"cached-{n}: cache write {c['cache_write']}, cache read {c['cached']}, "
                      f"uncached input {c['input_net']}: {text_of(msg)!r}")

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
