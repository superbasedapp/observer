"""A chatbot built on the superbased SDK directly, with no framework.

What it shows, per turn:
  * ``sb.admit()`` screens the user's message before the model runs;
  * the system prompt comes from the prompt registry (``get_prompt``, label
    production), compiled with a variable, and stamps the span with its version;
  * a manual LLM span around a raw OpenAI call, with ``set_usage`` (input,
    output, cached and reasoning tokens) and the response content;
  * a score per turn, and end-user feedback;
  * ``get_trace_cost()`` for the turn's trace once it is ingested;
  * the end user, session and customer tenant on every span.

Create the prompt first (see README.md). The OpenAI key comes from
OPENAI_API_KEY only. Every call uses gpt-5-nano.
"""

from __future__ import annotations

import json
import os
import sys
import time

from openai import OpenAI

import superbased_sdk as sb

MODEL = "gpt-5-nano"
SERVICE = os.environ.get("SUPERBASED_SERVICE_NAME", "sdk-direct-chatbot")
RUN_ID = os.environ.get("RUN_ID", str(int(time.time())))
PROMPT = os.environ.get("PROMPT_NAME", "support-system")

sb.init(service_name=SERVICE, release="examples-1")
client = OpenAI()

TURNS = [
    "Hi! What can you do?",
    "What is your return window?",
    "Tell me about competitor pricing.",  # the admission policy refuses this one
]


def answer(prompt: sb.Prompt, system: str, history: list, text: str) -> tuple[str, dict]:
    messages = [{"role": "system", "content": system}, *history, {"role": "user", "content": text}]
    # prompt=<Prompt> stamps the span with the registry prompt's name and
    # version (sbo.prompt.*); set_content records the messages actually sent.
    with sb.llm_span("chat", model=MODEL, provider="openai", prompt=prompt) as s:
        sb.set_content(s, prompt=messages)
        sb.set_request_params(s, max_tokens=400)
        resp = client.chat.completions.create(model=MODEL, messages=messages,
                                              max_completion_tokens=400, reasoning_effort="minimal")
        u = resp.usage
        usage = {
            "kind": "chat", "id": resp.id, "input": u.prompt_tokens, "output": u.completion_tokens,
            "cached": getattr(u.prompt_tokens_details, "cached_tokens", 0) or 0,
            "reasoning": getattr(u.completion_tokens_details, "reasoning_tokens", 0) or 0,
        }
        reply = resp.choices[0].message.content or ""
        # input_tokens is the gross input (cache reads are part of it);
        # output_tokens includes the reasoning tokens.
        sb.set_usage(s, input_tokens=usage["input"], output_tokens=usage["output"],
                     cache_read_tokens=usage["cached"], reasoning_tokens=usage["reasoning"],
                     finish_reasons=[resp.choices[0].finish_reason], response_id=resp.id,
                     response_model=resp.model, response=reply)
    return reply, usage


def main() -> int:
    user, session, tenant = "user-ada", f"sd-{RUN_ID}", "acme"
    prompt = sb.get_prompt(PROMPT, fallback="You are a terse support bot. Answer in one sentence.")
    print(f"prompt: {prompt.name} v{prompt.version} label={prompt.label!r}", file=sys.stderr)
    system = prompt.compile(company="Acme Widgets") if prompt.version else prompt.text

    trace_ids, calls, verdicts, scores = [], [], [], []
    history: list = []
    with sb.propagate_attributes(user=user, session_id=session, tenant=tenant):
        for i, text in enumerate(TURNS, 1):
            with sb.span(f"turn-{i}", kind=sb.AGENT) as root:
                tid = sb.get_current_trace_id()
                trace_ids.append(tid)
                sb.set_input(root, text)
                v = sb.admit(text)
                verdicts.append({"turn": i, "decision": v.decision, "allowed": v.allowed, "mode": v.mode,
                                 "degraded": v.degraded, "judge_used": v.judge_used})
                if not v.allowed:
                    reply = "Sorry, I can't help with that here."
                else:
                    reply, usage = answer(prompt, system, history, text)
                    calls.append(usage)
                    history += [{"role": "user", "content": text}, {"role": "assistant", "content": reply}]
                sb.set_output(root, reply)
                # A toy evaluator: a support answer should be short.
                r = sb.score("concise", len(reply) <= 240, scorer="length-check", scorer_version="1")
                scores.append({"turn": i, "ok": r.ok, "errors": r.errors})
            fb = sb.feedback(True, trace_id=tid, comment="helpful")
            scores.append({"turn": i, "feedback_ok": fb.ok, "errors": fb.errors})
            print(f"turn {i}: {text!r} -> {reply!r} (admit: {v.decision}{', ' + v.degraded if v.degraded else ''})")

    sb.flush()
    costs = {}
    for tid in trace_ids:
        cost = None
        for _ in range(20):  # the cost exists once the spans are ingested
            cost = sb.get_trace_cost(tid)
            if cost and cost.get("spans"):
                break
            time.sleep(1)
        costs[tid] = cost and {"cost_usd": cost.get("cost_usd"), "label": cost["cost_provenance"]["label"],
                               "from": cost.get("destination")}
        print(f"cost {tid}: {costs[tid]}")

    record = {"service": SERVICE, "run_id": RUN_ID, "user": user, "session": session, "tenant": tenant,
              "prompt": {"name": prompt.name, "version": prompt.version}, "trace_ids": trace_ids,
              "calls": calls, "verdicts": verdicts, "scores": scores, "costs": costs,
              "diagnostics": {k: v for k, v in sb.diagnostics().items()
                              if k in ("destination", "destinations", "failed_exports", "dropped_spans",
                                       "admission_degraded", "admission_last_error")}}
    with open(os.environ.get("RUN_OUT", "run.json"), "w") as f:
        json.dump(record, f, indent=2, default=str)
    print(json.dumps(record["diagnostics"], default=str), file=sys.stderr)
    sb.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
