"""A small dataset experiment with a CI gate (``fail_under``).

Runs a tiny golden set through the same model call the chatbot makes and
scores each answer with an exact-match evaluator. ``fail_under=0.5`` makes the
script exit 1 (``ExperimentGateFailed`` is a ``SystemExit``) when fewer than
half of the items pass.

On this machine the dataset is created on first use. On the organization the
dataset must exist first, and the key needs the ``sdk:eval`` scope (a CI
credential), plus ``sdk:read`` if the task fetches a managed prompt.
"""

from __future__ import annotations

import os
import sys
import time

import anthropic

import superbased_sdk as sb

sb.init(service_name=os.environ.get("SUPERBASED_SERVICE_NAME", "sdk-direct-anthropic-evals"))
client = anthropic.Anthropic()  # the task opens its own LLM span; sb.init() turned the SDK's own spans off
DATASET = os.environ.get("DATASET_NAME", "capitals-golden")

ITEMS = [
    {"id": "fr", "input": "Capital of France? One word.", "expected": "Paris"},
    {"id": "jp", "input": "Capital of Japan? One word.", "expected": "Tokyo"},
]


def task(input: str) -> str:
    with sb.llm_span("answer", model="claude-haiku-5-5", provider="anthropic", prompt=input) as s:
        resp = client.messages.create(
            model="claude-haiku-5-5", messages=[{"role": "user", "content": input}],
            max_tokens=300, output_config={"effort": "low"})
        out = "".join(b.text for b in resp.content if b.type == "text").strip().rstrip(".")
        u = resp.usage  # input_tokens is net of the cache: set_usage takes the gross input
        sb.set_usage(s, input_tokens=u.input_tokens + (u.cache_creation_input_tokens or 0) + (u.cache_read_input_tokens or 0),
                     output_tokens=u.output_tokens, response_id=resp.id, response_model=resp.model, response=out)
    return out


def exact_match(*, output, expected):
    return output.lower() == str(expected).lower()


exact_match.version = "1"

if __name__ == "__main__":
    result = sb.run_experiment(ITEMS, task, [exact_match], dataset_name=DATASET,
                               name=f"capitals-{int(time.time())}", fail_under=0.5)
    print("pass_rate:", result.pass_rate, "scored:", result.scored, "runs:", result.runs)
    print("errors:", result.errors)
    print("summary:", result.summary)
    sb.shutdown()
    sys.exit(0)
