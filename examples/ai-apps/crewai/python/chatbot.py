"""A small CrewAI chatbot traced to the superbased app on this machine.

One crew, one agent, one task and one tool, on OpenAI's gpt-5-nano. The
superbased SDK exports every span to the machine's OTLP receiver
(destination ``local`` unless ``SUPERBASED_DESTINATION`` or a signed-in
machine says otherwise, as in the other examples): crew, task and agent spans
from the CrewAI instrumentor, and the model calls as LLM spans from the OpenAI
instrumentor.

    python chatbot.py "How many letters are in the capital of France?"

Needs OPENAI_API_KEY in the environment. See README.md.
"""

import os
import sys
import uuid

# CrewAI reads these at import time: no anonymous usage telemetry to CrewAI,
# no CrewAI-hosted tracing (and no end-of-run prompt asking to turn it on).
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

import superbased_sdk as sb  # noqa: E402

MODEL = os.environ.get("CHATBOT_MODEL", "gpt-5-nano")


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is not set", file=sys.stderr)
        return 2
    question = " ".join(sys.argv[1:]) or "How many letters are in the capital of France?"
    session_id = os.environ.get("CHATBOT_SESSION_ID") or f"crewai-chat-{uuid.uuid4().hex[:8]}"

    # No destination here: the SDK takes SUPERBASED_DESTINATION, else the
    # machine's default (local on a machine that is not signed in), so the
    # same example runs to the machine, the organization or both.
    sb.init(
        service_name="crewai-chatbot",
        user=os.environ.get("CHATBOT_USER", "demo-user"),
        session_id=session_id,
    )
    # After init(), so the instrumentors use the SDK's provider. "crewai"
    # gives the crew, task and agent spans; "openai" gives the model calls.
    print("instrument:", sb.instrument(["crewai", "openai"]))

    from crewai import LLM, Agent, Crew, Task
    from crewai.tools import tool

    @tool("word_length")
    def word_length(word: str) -> int:
        """Count the letters in one word."""
        return len(word.strip())

    # gpt-5-nano is a reasoning model: no temperature, and its reasoning
    # tokens count against max_completion_tokens, so leave headroom.
    llm = LLM(model=MODEL, max_completion_tokens=4000, reasoning_effort="low")

    agent = Agent(
        role="Geography helper",
        goal="Answer short geography questions accurately",
        backstory="You answer in one sentence and use your tools for counting.",
        tools=[word_length],
        llm=llm,
        max_iter=3,
        verbose=False,
    )
    task = Task(
        description=f"Answer the question: {question} Use the word_length tool for any letter count.",
        expected_output="One sentence.",
        agent=agent,
    )
    crew = Crew(agents=[agent], tasks=[task], verbose=False)
    result = crew.kickoff()

    print("answer:", str(result).strip())
    usage = result.token_usage
    print(
        f"crewai usage: requests={usage.successful_requests} prompt={usage.prompt_tokens} "
        f"completion={usage.completion_tokens} total={usage.total_tokens}"
    )
    print("session:", session_id)

    sb.shutdown()  # flush before exit; bounded, never raises
    d = sb.diagnostics()
    if d.get("failed_exports"):
        print(f"export failed: {d.get('last_error')}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
