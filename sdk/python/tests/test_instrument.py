"""W2-3: instrument([...]) over the OpenInference instrumentors, offline.

Each target runs a scenario against a mocked transport (no network) and the
emitted spans are checked against sdk/contract/fixtures/instrument/<target>.json:
the span names, the parent links and the recorded attributes. The same
fixtures' "want" blocks (the normalized genaiattr fields) are checked by
go test ./tests/sdkcontract, so the chain instrumentor -> wire attributes ->
normalized span is pinned end to end.

Re-record after an instrumentor upgrade with SUPERBASED_RECORD_FIXTURES=1
(keeps each span's "want"; review the diff).
"""

import asyncio
import json
import os
import re

import pytest

import superbased_sdk as sb
from superbased_sdk import _instrument

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "fixtures", "instrument")
RECORD = os.environ.get("SUPERBASED_RECORD_FIXTURES") == "1"

# Attributes whose values are not deterministic across runs (or across
# library patch versions) and so are not recorded.
VOLATILE = {
    "langchain": {"metadata"},  # carries per-run LangGraph checkpoint ids
    # pydantic-ai's own dump of its ModelRequestParameters dataclass: every
    # pydantic-ai release adds fields (2.71 has eight more than 2.54, the
    # newest release Python 3.10 gets), and no vocabulary key maps it.
    "pydantic-ai": {"model_request_parameters"},
}


def _mock_http(module_with_httpx, handler):
    """A client transport for the httpx flavour the library uses (anthropic 2.x
    ships its own httpx2)."""
    hx = getattr(module_with_httpx, "httpx2", None) or getattr(module_with_httpx, "httpx")

    def h(request):
        status, body = handler(request)
        return hx.Response(status, json=body)

    return hx.Client(transport=hx.MockTransport(h))


# --- scenarios ------------------------------------------------------------------


def scenario_openai():
    openai = pytest.importorskip("openai")
    import openai._base_client as base

    def handler(req):
        if req.url.path.endswith("/embeddings"):
            return 200, {
                "object": "list",
                "data": [{"object": "embedding", "index": 0, "embedding": [0.25, 0.5]}],
                "model": "text-embedding-3-small",
                "usage": {"prompt_tokens": 5, "total_tokens": 5},
            }
        return 200, {
            "id": "chatcmpl-fixture",
            "object": "chat.completion",
            "created": 1763510400,
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Paris."}}],
            "usage": {
                "prompt_tokens": 1200,
                "completion_tokens": 40,
                "total_tokens": 1240,
                "prompt_tokens_details": {"cached_tokens": 1024},
                "completion_tokens_details": {"reasoning_tokens": 16},
            },
        }

    client = openai.OpenAI(api_key="sk-fixture", base_url="http://mock.invalid/v1", http_client=_mock_http(base, handler))
    with sb.propagate_attributes(user="end-user-1", session_id="sess-1"):
        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Capital of France?"}],
            temperature=0.2,
        )
        client.embeddings.create(model="text-embedding-3-small", input="hello", encoding_format="float")


def scenario_anthropic():
    anthropic = pytest.importorskip("anthropic")
    import anthropic._base_client as base

    def handler(req):
        return 200, {
            "id": "msg_fixture",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-5",
            "content": [{"type": "text", "text": "Paris."}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 30, "output_tokens": 5, "cache_read_input_tokens": 2000, "cache_creation_input_tokens": 100},
        }

    client = anthropic.Anthropic(api_key="sk-fixture", base_url="http://mock.invalid", http_client=_mock_http(base, handler))
    client.messages.create(
        model="claude-sonnet-4-5", max_tokens=64, system="Be brief.", messages=[{"role": "user", "content": "Capital of France?"}]
    )


def scenario_langchain():
    pytest.importorskip("langchain_core")
    graph = pytest.importorskip("langgraph.graph")
    from typing import TypedDict

    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage, HumanMessage
    from langchain_core.tools import tool

    @tool
    def word_length(word: str) -> int:
        """Length of a word."""
        return len(word)

    model = GenericFakeChatModel(
        messages=iter([AIMessage(content="superbased has 10 letters", usage_metadata={"input_tokens": 12, "output_tokens": 6, "total_tokens": 18})])
    )

    class State(TypedDict, total=False):
        q: str
        n: int
        a: str

    def count(s):
        return {"n": word_length.invoke({"word": s["q"]})}

    def answer(s):
        return {"a": model.invoke([HumanMessage(content=f"{s['q']} has {s['n']} letters?")]).content}

    g = graph.StateGraph(State)
    g.add_node("count", count)
    g.add_node("answer", answer)
    g.add_edge(graph.START, "count")
    g.add_edge("count", "answer")
    g.add_edge("answer", graph.END)
    g.compile().invoke({"q": "superbased"})


def scenario_mcp():
    pytest.importorskip("mcp")
    try:
        from mcp.client.client import Client
        from mcp.server.mcpserver import MCPServer
    except ImportError:
        pytest.skip("the MCP scenario needs mcp >= 2")

    server = MCPServer("fixture")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        with sb.tool_span("server.add", arguments={"a": a, "b": b}) as t:
            sb.set_tool_result(t, a + b)
        return a + b

    async def main():
        async with Client(server) as c:
            with sb.span("client.call"):
                await c.call_tool("add", {"a": 2, "b": 3})

    asyncio.run(main())


def _mock_async_http(module_with_httpx, handler):
    hx = getattr(module_with_httpx, "httpx2", None) or getattr(module_with_httpx, "httpx")

    def h(request):
        status, body = handler(request)
        return hx.Response(status, json=body)

    return hx.AsyncClient(transport=hx.MockTransport(h))


# --- Wave 5 (W5-1) scenarios -------------------------------------------------------


_GEMINI_RESPONSE = {
    "candidates": [{"content": {"role": "model", "parts": [{"text": "Paris."}]}, "finishReason": "STOP", "index": 0}],
    "usageMetadata": {
        "promptTokenCount": 1200,
        "candidatesTokenCount": 40,
        "thoughtsTokenCount": 16,
        "cachedContentTokenCount": 1024,
        "totalTokenCount": 1256,
    },
    "modelVersion": "gemini-2.5-flash-001",
    "responseId": "resp-gemini-fixture",
}


def scenario_gemini():
    genai = pytest.importorskip("google.genai")
    import httpx
    from google.genai import types

    def handler(request):
        return httpx.Response(200, json=_GEMINI_RESPONSE)

    def client(**kw):
        opts = types.HttpOptions(httpx_client=httpx.Client(transport=httpx.MockTransport(handler)))
        return genai.Client(http_options=opts, **kw)

    config = types.GenerateContentConfig(system_instruction="Be brief.", temperature=0.2, max_output_tokens=64)
    # The Gemini API (an API key) ...
    with sb.span("gemini-api"):
        client(api_key="fixture-key").models.generate_content(model="gemini-2.5-flash", contents="Capital of France?", config=config)
    # ... and Vertex AI (vertexai=True), through the same SDK.
    from google.oauth2.credentials import Credentials

    creds = Credentials(token="fixture-token")  # a static token: never refreshed, never sent anywhere real
    with sb.span("vertex-ai"):
        client(vertexai=True, project="fixture-project", location="us-central1", credentials=creds).models.generate_content(
            model="gemini-2.5-flash", contents="Capital of France?", config=config
        )


class _RawBody:
    """The urllib3-like raw body botocore reads a mocked response from."""

    def __init__(self, data):
        import io

        self._io = io.BytesIO(data)

    def stream(self, **_):
        data = self._io.read()
        if data:
            yield data

    def read(self, *a, **kw):
        return self._io.read(*a)

    def close(self):
        pass


def scenario_bedrock():
    boto3 = pytest.importorskip("boto3")
    from botocore.awsrequest import AWSResponse

    converse = {
        "output": {"message": {"role": "assistant", "content": [{"text": "Paris."}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 30, "outputTokens": 5, "totalTokens": 2135, "cacheReadInputTokens": 2000, "cacheWriteInputTokens": 100},
        "metrics": {"latencyMs": 120},
    }
    invoke = {
        "id": "msg_bedrock_fixture",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-5",
        "content": [{"type": "text", "text": "Paris."}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 30, "output_tokens": 5},
    }

    def before_send(request, **_):
        body = converse if request.url.endswith("/converse") else invoke
        data = json.dumps(body).encode()
        headers = {"content-type": "application/json", "x-amzn-requestid": "req-bedrock-fixture", "content-length": str(len(data))}
        return AWSResponse(request.url, 200, headers, _RawBody(data))

    client = boto3.client(
        "bedrock-runtime", region_name="us-east-1", aws_access_key_id="AKIDFIXTURE", aws_secret_access_key="fixture-secret"
    )
    client.meta.events.register("before-send", before_send)
    model = "anthropic.claude-sonnet-4-5-20250929-v1:0"
    client.converse(
        modelId=model,
        system=[{"text": "Be brief."}],
        messages=[{"role": "user", "content": [{"text": "Capital of France?"}]}],
        inferenceConfig={"maxTokens": 64, "temperature": 0.2},
    )
    client.invoke_model(
        modelId=model,
        body=json.dumps(
            {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 64, "messages": [{"role": "user", "content": "Capital of France?"}]}
        ),
    ).get("body").read()


def scenario_llama_index():
    pytest.importorskip("llama_index.core")
    llms_openai = pytest.importorskip("llama_index.llms.openai")
    import openai._base_client as base
    from llama_index.core import Document, VectorStoreIndex
    from llama_index.core.embeddings import MockEmbedding

    def handler(req):
        return 200, {
            "id": "chatcmpl-llama-fixture",
            "object": "chat.completion",
            "created": 1763510400,
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Paris."}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 3, "total_tokens": 123, "prompt_tokens_details": {"cached_tokens": 64}},
        }

    llm = llms_openai.OpenAI(
        model="gpt-4o-mini", api_key="sk-fixture", api_base="http://mock.invalid/v1", http_client=_mock_http(base, handler), max_retries=0
    )
    embed = MockEmbedding(embed_dim=4)
    index = VectorStoreIndex.from_documents([Document(text="Paris is the capital of France.", doc_id="doc-1")], embed_model=embed)
    index.as_query_engine(llm=llm, similarity_top_k=1).query("Capital of France?")


def scenario_crewai():
    os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
    crewai = pytest.importorskip("crewai")
    from crewai.llms.base_llm import BaseLLM

    class FixtureLLM(BaseLLM):
        def call(self, messages, *args, **kwargs):
            return "Thought: I know the answer.\nFinal Answer: Paris."

        def supports_function_calling(self):
            return False

    llm = FixtureLLM(model="fixture-model")
    agent = crewai.Agent(role="Geographer", goal="Answer capital questions", backstory="Knows capitals.", llm=llm, verbose=False)
    task = crewai.Task(description="Capital of France?", expected_output="A city name.", agent=agent)
    crewai.Crew(agents=[agent], tasks=[task], verbose=False).kickoff()


def scenario_pydantic_ai():
    pai = pytest.importorskip("pydantic_ai")
    from pydantic_ai.models.test import TestModel

    agent = pai.Agent(TestModel(custom_output_text="Paris."), name="geographer", instructions="Be brief.")

    @agent.tool_plain
    def word_length(word: str) -> int:
        """Length of a word."""
        return len(word)

    agent.run_sync("Capital of France?")


def scenario_openai_agents():
    agents = pytest.importorskip("agents")
    openai = pytest.importorskip("openai")
    import openai._base_client as base

    calls = []

    def handler(req):
        calls.append(req)
        usage = {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60, "prompt_tokens_details": {"cached_tokens": 32}}
        if len(calls) == 1:
            msg = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "call_fixture", "type": "function", "function": {"name": "word_length", "arguments": "{\"word\": \"Paris\"}"}}
                ],
            }
            finish = "tool_calls"
        else:
            msg, finish = {"role": "assistant", "content": "Paris has 5 letters."}, "stop"
        return 200, {
            "id": f"chatcmpl-agents-{len(calls)}",
            "object": "chat.completion",
            "created": 1763510400,
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{"index": 0, "finish_reason": finish, "message": msg}],
            "usage": usage,
        }

    client = openai.AsyncOpenAI(api_key="sk-fixture", base_url="http://mock.invalid/v1", http_client=_mock_async_http(base, handler))

    @agents.function_tool
    def word_length(word: str) -> int:
        """Length of a word."""
        return len(word)

    agent = agents.Agent(
        name="assistant",
        instructions="Be brief.",
        tools=[word_length],
        model=agents.OpenAIChatCompletionsModel(model="gpt-4o-mini", openai_client=client),
    )
    agents.Runner.run_sync(agent, "How many letters in the capital of France?")


SCENARIOS = {
    "openai": scenario_openai,
    "anthropic": scenario_anthropic,
    "langchain": scenario_langchain,
    "mcp": scenario_mcp,
    "gemini": scenario_gemini,
    "bedrock": scenario_bedrock,
    "llama-index": scenario_llama_index,
    "crewai": scenario_crewai,
    "pydantic-ai": scenario_pydantic_ai,
    "openai-agents": scenario_openai_agents,
}


# --- harness --------------------------------------------------------------------


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ADDR = re.compile(r" at 0x[0-9a-f]+")  # an object repr's memory address (LlamaIndex prompt reprs)


def _jsonable(v):
    """A JSON-ready attribute value with per-run ids (LangChain run ids in a
    serialized message, CrewAI crew and task ids) replaced by <id> and object
    addresses by 0x<addr>."""
    if isinstance(v, tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, str):
        return _ADDR.sub(" at 0x<addr>", _UUID.sub("<id>", v))
    return v


def _run(target, mem):
    sb.init(exporter=mem)
    status = sb.instrument([target])
    if status[target] == _instrument.NOT_INSTALLED:
        pytest.skip(f"{target}: instrumentor or library not installed")
    assert status[target] == _instrument.INSTRUMENTED, status
    try:
        SCENARIOS[target]()
    finally:
        sb.uninstrument([target])
    assert sb.flush(5)
    return list(mem.get_finished_spans())


def _load(target):
    path = os.path.join(FIXTURES, target + ".json")
    if not os.path.exists(path):
        if RECORD:
            return path, {"target": target, "spans": []}
        pytest.skip("sdk/contract fixtures are not present (an sdist)")
    with open(path, encoding="utf-8") as f:
        return path, json.load(f)


def _ordered(emitted):
    """The spans in start order, each with its normalized name and its
    occurrence number among spans of that name (a fixture span is matched by
    name and occurrence, since a framework repeats names: two model calls, two
    agent turns)."""
    seen = {}
    out = []
    for s in sorted(emitted, key=lambda s: (s.start_time, s.context.span_id)):
        name = _jsonable(s.name)
        n = seen.get(name, 0)
        seen[name] = n + 1
        out.append((name, n, s))
    return out


@pytest.mark.parametrize("target", sorted(SCENARIOS))
def test_instrument_conformance(target, mem):
    path, fx = _load(target)
    emitted = _run(target, mem)
    by_id = {s.context.span_id: s for s in emitted}
    volatile = VOLATILE.get(target, set())
    ordered = _ordered(emitted)

    def parent_name(s):
        p = by_id.get(s.parent.span_id) if s.parent is not None else None
        return _jsonable(p.name) if p is not None else None

    def occurrences(spans):
        seen = {}
        for sp in spans:
            n = seen.get(sp["name"], 0)
            seen[sp["name"]] = n + 1
            yield (sp["name"], n), sp

    if RECORD:
        wants = {key: sp.get("want", {}) for key, sp in occurrences(fx.get("spans", []))}
        fx["spans"] = [
            {
                "name": name,
                "parent": parent_name(s),
                "attrs": {k: _jsonable(v) for k, v in sorted(s.attributes.items()) if k not in volatile},
                "want": wants.get((name, n), {}),
            }
            for name, n, s in ordered
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(fx, f, indent=2, ensure_ascii=False)
            f.write("\n")
        return

    assert fx["spans"], f"{path} lists no spans"
    got_by_key = {(name, n): s for name, n, s in ordered}
    names = [name for name, _, _ in ordered]
    for key, want in occurrences(fx["spans"]):
        assert key in got_by_key, f"{target}: no span {key[0]!r} #{key[1] + 1} (got {names})"
        got = got_by_key[key]
        assert parent_name(got) == want["parent"], f"{want['name']}: parent {parent_name(got)!r} != {want['parent']!r}"
        attrs = {k: _jsonable(v) for k, v in got.attributes.items()}
        for k, v in want["attrs"].items():
            if k in volatile:
                continue
            assert attrs.get(k) == v, f"{target}/{want['name']}: {k} = {attrs.get(k)!r}, fixture {v!r}"


def test_mcp_server_spans_join_the_client_trace(mem):
    path, fx = _load("mcp")
    emitted = _run("mcp", mem)
    client = next(s for s in emitted if s.name == "client.call")
    server_tool = next(s for s in emitted if s.name == "server.add")
    assert server_tool.context.trace_id == client.context.trace_id


def test_identity_reaches_instrumentor_spans(mem):
    emitted = _run("openai", mem)
    for s in emitted:
        assert s.attributes["sbo.user"] == "end-user-1" and s.attributes["session.id"] == "sess-1"


def test_capture_off_and_mask_apply_to_instrumentor_spans(mem):
    if not _instrument.available()["openai"]:
        pytest.skip("openai instrumentor not installed")
    sb.init(exporter=mem, mask=lambda v, k: "[masked]")
    assert sb.instrument(["openai"])["openai"] == _instrument.INSTRUMENTED
    try:
        scenario_openai()
    finally:
        sb.uninstrument(["openai"])
    assert sb.flush(5)
    chat = next(s for s in mem.get_finished_spans() if s.name == "ChatCompletion")
    assert chat.attributes["llm.input_messages.1.message.content"] == "[masked]"
    assert chat.attributes["llm.input_messages.1.message.role"] == "user"
    assert chat.attributes["input.value"] == "[masked]"
    emb = next(s for s in mem.get_finished_spans() if s.name == "CreateEmbeddings")
    assert emb.attributes["embedding.embeddings.0.embedding.text"] == "[masked]"


# --- the API itself ----------------------------------------------------------------


def test_instrument_statuses(mem):
    sb.init(exporter=mem)
    with pytest.raises(ValueError):
        sb.instrument(["no-such-framework"])
    assert set(sb.instrument([])) == set()
    out = sb.instrument("langgraph")  # alias, str accepted
    assert list(out) == ["langchain"]
    if out["langchain"] == _instrument.INSTRUMENTED:
        assert sb.instrument(["langchain"]) == {"langchain": _instrument.ALREADY}
        assert "langchain" in _instrument.instrumented()
    sb.uninstrument()
    sb.uninstrument(["openai"])  # never instrumented: no error
    assert _instrument.instrumented() == []


def test_not_installed_is_reported(monkeypatch, mem):
    sb.init(exporter=mem)
    monkeypatch.setattr(_instrument, "_load", lambda t: None)
    assert sb.instrument() == {t.name: _instrument.NOT_INSTALLED for t in _instrument.TARGETS}


def test_instrumentor_error_is_reported(monkeypatch, mem):
    class Boom:
        _is_instrumented_by_opentelemetry = False

        def _check_dependency_conflicts(self):
            return None

        def instrument(self, **kw):
            raise RuntimeError("broken")

    sb.init(exporter=mem)
    monkeypatch.setattr(_instrument, "_load", lambda t: Boom)
    out = sb.instrument(["openai"])
    assert out["openai"].startswith("error: RuntimeError: broken")
    assert _instrument.instrumented() == []


def test_every_target_has_a_fixture():
    if not os.path.isdir(FIXTURES):
        pytest.skip("sdk/contract fixtures are not present (an sdist)")
    for t in _instrument.TARGETS:
        assert os.path.exists(os.path.join(FIXTURES, t.name + ".json")), t.name


# --- Wave 5 (W5-1) API cases ----------------------------------------------------------


def test_new_target_aliases(mem):
    sb.init(exporter=mem)
    assert _instrument._names(["vertex", "google_genai", "VertexAI"]) == ["gemini"]
    assert _instrument._names(["llama_index", "llamaindex"]) == ["llama-index"]
    assert _instrument._names(["agents", "openai_agents", "pydantic_ai", "boto3", "crewai"]) == [
        "openai-agents",
        "pydantic-ai",
        "bedrock",
        "crewai",
    ]
    with pytest.raises(ValueError) as e:
        _instrument._names(["vertex-ai-legacy"])
    assert "gemini" in str(e.value) and "vertex" in str(e.value)


def test_every_target_is_reported(monkeypatch, mem):
    sb.init(exporter=mem)
    monkeypatch.setattr(_instrument, "_load", lambda t: None)
    out = sb.instrument()
    assert set(out) == {
        "openai", "anthropic", "langchain", "mcp",
        "gemini", "bedrock", "llama-index", "crewai", "pydantic-ai", "openai-agents",
    }


def _pydantic_ai_or_skip():
    if not _instrument.available()["pydantic-ai"]:
        pytest.skip("pydantic-ai or its OpenInference package not installed")
    import pydantic_ai

    return pydantic_ai


def test_pydantic_ai_enricher_exports_a_copy_and_uninstrument_restores(mem):
    pai = _pydantic_ai_or_skip()
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from superbased_sdk import _export

    host = InMemorySpanExporter()  # a host processor that sees the ORIGINAL spans
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(host))
    sb.init(exporter=mem, tracer_provider=provider)
    previous = pai.Agent._instrument_default
    assert sb.instrument(["pydantic-ai"]) == {"pydantic-ai": _instrument.INSTRUMENTED}
    assert "pydantic-ai" in _export.ENRICHERS
    try:
        scenario_pydantic_ai()
    finally:
        sb.uninstrument(["pydantic-ai"])
    assert sb.flush(5)
    exported = {s.name: s for s in mem.get_finished_spans()}
    original = {s.name: s for s in host.get_finished_spans()}
    assert exported["invoke_agent geographer"].attributes["openinference.span.kind"] == "AGENT"
    assert "openinference.span.kind" not in original["invoke_agent geographer"].attributes
    # uninstrument: the enricher is gone and Pydantic AI's default is restored.
    assert "pydantic-ai" not in _export.ENRICHERS
    assert pai.Agent._instrument_default == previous


def test_pydantic_ai_host_instrumented_is_already(mem):
    pai = _pydantic_ai_or_skip()
    sb.init(exporter=mem)
    pai.Agent.instrument_all(True)  # the host turned Pydantic AI's spans on itself
    try:
        assert sb.instrument(["pydantic-ai"]) == {"pydantic-ai": _instrument.ALREADY}
    finally:
        pai.Agent.instrument_all(False)


def test_enricher_failure_never_breaks_export(mem):
    from superbased_sdk import _export

    def boom(attrs):
        raise RuntimeError("enricher bug")

    sb.init(exporter=mem)
    _export.ENRICHERS["test"] = boom
    try:
        with sb.span("plain"):
            pass
    finally:
        _export.ENRICHERS.pop("test", None)
    assert sb.flush(5)
    assert [s.name for s in mem.get_finished_spans()] == ["plain"]


def test_capture_off_strips_the_new_extra_content_keys(mem):
    _pydantic_ai_or_skip()
    sb.init(exporter=mem, capture_content=False)
    assert sb.instrument(["pydantic-ai"])["pydantic-ai"] == _instrument.INSTRUMENTED
    try:
        scenario_pydantic_ai()
    finally:
        sb.uninstrument(["pydantic-ai"])
    assert sb.flush(5)
    for s in mem.get_finished_spans():
        for k in s.attributes:
            assert not sb._keys.is_content_key(k), (s.name, k)
        assert "final_result" not in s.attributes and "pydantic_ai.all_messages" not in s.attributes
    agent = next(s for s in mem.get_finished_spans() if s.name == "invoke_agent geographer")
    assert agent.attributes["gen_ai.agent.name"] == "geographer"  # metadata stays


def test_mask_reaches_llama_index_documents(mem):
    if not _instrument.available()["llama-index"]:
        pytest.skip("llama-index not installed")
    pytest.importorskip("llama_index.llms.openai")
    sb.init(exporter=mem, mask=lambda v, k: "[masked]")
    assert sb.instrument(["llama-index"])["llama-index"] == _instrument.INSTRUMENTED
    try:
        scenario_llama_index()
    finally:
        sb.uninstrument(["llama-index"])
    assert sb.flush(5)
    retr = next(s for s in mem.get_finished_spans() if s.name == "VectorIndexRetriever.retrieve")
    assert retr.attributes["retrieval.documents.0.document.content"] == "[masked]"
