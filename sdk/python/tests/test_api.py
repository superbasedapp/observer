"""W2-2: per-request attributes, typed span helpers, usage keys, sampling,
should_export, masking and trace-context helpers."""

import asyncio
import contextvars
import json
import threading

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _config, _pipeline


def spans(mem):
    assert sb.flush(5)
    return {s.name: s for s in mem.get_finished_spans()}


# --- propagate_attributes / identify -----------------------------------------------


def test_propagate_attributes_stamps_children_and_current(mem):
    sb.init(exporter=mem)
    with sb.span("root"):
        with sb.propagate_attributes(user="u1", session_id="s1", tenant="t1", tags=["b", "a"], metadata={"k": "v", "n": 3}, release="r1", environment="prod"):
            with sb.span("child"):
                pass
        with sb.span("after"):
            pass
    got = spans(mem)
    for name in ("root", "child"):
        a = got[name].attributes
        assert a["sbo.user"] == "u1" and a["session.id"] == "s1" and a["sbo.tenant"] == "t1"
        assert a["sbo.release"] == "r1" and a["sbo.environment"] == "prod"
        assert tuple(a["sbo.tags"]) == ("a", "b")
        assert a["sbo.metadata.k"] == "v" and a["sbo.metadata.n"] == "3"
    assert "sbo.user" not in got["after"].attributes


def test_nested_scopes_merge_inner_wins_tags_union(mem):
    sb.init(exporter=mem)
    with sb.propagate_attributes(user="outer", tags=["x"], metadata={"a": "1", "b": "1"}):
        with sb.propagate_attributes(user="inner", tags=["y"], metadata={"b": "2"}):
            assert sb.get_current_attributes() == {"user": "inner", "tags": ["x", "y"], "metadata": {"a": "1", "b": "2"}}
            with sb.span("in"):
                pass
        with sb.propagate_attributes(user=""):  # "" clears for the inner scope
            with sb.span("cleared"):
                pass
    got = spans(mem)
    assert got["in"].attributes["sbo.user"] == "inner"
    assert tuple(got["in"].attributes["sbo.tags"]) == ("x", "y")
    assert "sbo.user" not in got["cleared"].attributes


def test_span_own_value_is_never_overwritten(mem):
    sb.init(exporter=mem)
    with sb.propagate_attributes(user="ctx"):
        with sb.span("own", attributes={"sbo.user": "explicit"}):
            pass
    assert spans(mem)["own"].attributes["sbo.user"] == "explicit"


def test_identify_until_reset(mem):
    sb.init(exporter=mem)
    h = sb.identify(user="alice")
    with sb.span("a"):
        pass
    h.reset()
    h.reset()  # idempotent
    with sb.span("b"):
        pass
    got = spans(mem)
    assert got["a"].attributes["sbo.user"] == "alice"
    assert "sbo.user" not in got["b"].attributes


def test_identify_is_task_scoped(mem):
    sb.init(exporter=mem)

    async def handler(user):
        sb.identify(user=user)
        await asyncio.sleep(0.01)
        with sb.span("req-" + user):
            pass

    async def main():
        await asyncio.gather(handler("u1"), handler("u2"))

    asyncio.run(main())
    got = spans(mem)
    assert got["req-u1"].attributes["sbo.user"] == "u1"
    assert got["req-u2"].attributes["sbo.user"] == "u2"
    assert sb.get_current_attributes() == {}


def test_propagate_attributes_async_and_copy_context(mem):
    sb.init(exporter=mem)

    async def work():
        with sb.propagate_attributes(session_id="sess"):
            await asyncio.sleep(0)
            with sb.span("async"):
                pass

    asyncio.run(work())

    with sb.propagate_attributes(tenant="T"):
        ctx = contextvars.copy_context()
    t = threading.Thread(target=lambda: ctx.run(lambda: sb.span("thread").__enter__().end()))
    t.start()
    t.join()
    got = spans(mem)
    assert got["async"].attributes["session.id"] == "sess"
    assert got["thread"].attributes["sbo.tenant"] == "T"


def test_limits_follow_otelident(mem):
    sb.init(exporter=mem)
    tags = [f"t{i:02d}" for i in range(40)] + ["  ", "x" * 300]
    meta = {f"k{i:02d}": "v" * 600 for i in range(40)}
    with sb.propagate_attributes(tags=tags, metadata=meta, user="u" * 300):
        with sb.span("big"):
            pass
    a = spans(mem)["big"].attributes
    assert len(a["sbo.tags"]) == 32 and all(len(t) <= 128 for t in a["sbo.tags"])
    meta_keys = [k for k in a if k.startswith("sbo.metadata.")]
    assert len(meta_keys) == 32 and "sbo.metadata.k00" in a
    assert len(a["sbo.metadata.k00"]) == 512
    assert len(a["sbo.user"]) == 256


def test_metadata_must_be_mapping():
    with pytest.raises(TypeError):
        with sb.propagate_attributes(metadata=["x"]):
            pass


def test_init_identity_on_resource(mem):
    sb.init(exporter=mem, release="1.2.3", environment="staging", tags=["svc"], metadata={"team": "ml"})
    with sb.propagate_attributes(tags=["req"]):
        with sb.span("s"):
            pass
    sp = spans(mem)["s"]
    res = sp.resource.attributes
    assert res["service.version"] == "1.2.3" and res["deployment.environment.name"] == "staging"
    assert tuple(res["sbo.tags"]) == ("svc",) and res["sbo.metadata.team"] == "ml"
    assert tuple(sp.attributes["sbo.tags"]) == ("req",)  # span level; ingest unions with the resource


def test_init_identity_env(monkeypatch):
    env = {"SUPERBASED_RELEASE": "r", "SUPERBASED_ENVIRONMENT": "e", "SUPERBASED_TAGS": "b, a,", "SUPERBASED_METADATA": "x=1,y=2"}
    s = _config.Settings.resolve(env)
    assert (s.release, s.environment, s.tags, s.metadata) == ("r", "e", ("a", "b"), (("x", "1"), ("y", "2")))


def test_attached_mode_stamps_init_tags_with_union(mem):
    host = TracerProvider()
    host.add_span_processor(SimpleSpanProcessor(InMemorySpanExporter()))
    trace.set_tracer_provider(host)
    sb.init(exporter=mem, tags=["init"], user="u0")
    with sb.propagate_attributes(tags=["ctx"]):
        with sb.span("s"):
            pass
    a = spans(mem)["s"].attributes
    assert tuple(a["sbo.tags"]) == ("ctx", "init")
    assert a["sbo.user"] == "u0"


# --- typed spans and setters ----------------------------------------------------


def test_typed_span_helpers(mem):
    sb.init(exporter=mem)
    with sb.agent_span("planner", agent_id="ag-1"):
        with sb.tool_span("search", call_id="c1", arguments={"q": "x"}) as t:
            sb.set_tool_result(t, ["hit"])
        with sb.retriever_span("kb", query="what") as r:
            sb.set_documents(r, ["doc a", {"id": "2", "content": "doc b"}])
        with sb.embedding_span("embed", model="text-embedding-3-small", provider="openai") as e:
            sb.set_usage(e, input_tokens=12)
    g = spans(mem)
    a = g["planner"].attributes
    assert a["openinference.span.kind"] == "AGENT" and a["gen_ai.operation.name"] == "invoke_agent"
    assert a["gen_ai.agent.name"] == "planner" and a["agent.name"] == "planner" and a["gen_ai.agent.id"] == "ag-1"
    t = g["search"].attributes
    assert t["openinference.span.kind"] == "TOOL" and t["gen_ai.operation.name"] == "execute_tool"
    assert t["gen_ai.tool.name"] == "search" and t["tool.name"] == "search" and t["gen_ai.tool.call.id"] == "c1"
    assert json.loads(t["gen_ai.tool.call.arguments"]) == {"q": "x"}
    assert json.loads(t["gen_ai.tool.call.result"]) == ["hit"]
    r = g["kb"].attributes
    assert r["openinference.span.kind"] == "RETRIEVER" and r["gen_ai.operation.name"] == "retrieval"
    assert r["gen_ai.retrieval.query.text"] == "what"
    assert json.loads(r["gen_ai.retrieval.documents"]) == [{"content": "doc a"}, {"id": "2", "content": "doc b"}]
    e = g["embed"].attributes
    assert e["openinference.span.kind"] == "EMBEDDING" and e["gen_ai.operation.name"] == "embeddings"
    assert e["gen_ai.request.model"] == "text-embedding-3-small" and e["gen_ai.provider.name"] == "openai"
    assert e["gen_ai.usage.input_tokens"] == 12
    assert g["search"].parent.span_id == g["planner"].context.span_id


def test_set_usage_cache_and_reasoning(mem):
    sb.init(exporter=mem)
    with sb.llm_span("chat", model="m", provider="anthropic") as s:
        sb.set_usage(
            s, input_tokens=1000, output_tokens=200, total_tokens=1200, cache_read_tokens=800,
            cache_write_tokens=100, reasoning_tokens=150, finish_reasons=["stop"], response_model="m-1",
        )
    a = spans(mem)["chat"].attributes
    assert a["gen_ai.usage.cache_read.input_tokens"] == 800
    assert a["gen_ai.usage.cache_write.input_tokens"] == 100
    assert a["gen_ai.usage.reasoning.output_tokens"] == 150
    assert a["gen_ai.usage.total_tokens"] == 1200
    assert tuple(a["gen_ai.response.finish_reasons"]) == ("stop",)


def test_set_usage_rejects_negative_without_partial_write(mem):
    sb.init(exporter=mem)
    with sb.llm_span("chat") as s:
        with pytest.raises(ValueError):
            sb.set_usage(s, input_tokens=5, cache_read_tokens=-1)
    assert "gen_ai.usage.input_tokens" not in spans(mem)["chat"].attributes


def test_message_lists_and_system(mem):
    sb.init(exporter=mem)
    msgs = [{"role": "user", "content": "hi"}]
    with sb.llm_span("chat", prompt=msgs, system="be brief") as s:
        sb.set_content(s, response=[{"role": "assistant", "content": "yo"}])
    a = spans(mem)["chat"].attributes
    assert json.loads(a["gen_ai.input.messages"]) == msgs
    assert json.loads(a["gen_ai.output.messages"])[0]["content"] == "yo"
    assert a["gen_ai.system_instructions"] == "be brief"


def test_request_params_and_io(mem):
    sb.init(exporter=mem)
    with sb.llm_span("chat") as s:
        sb.set_request_params(s, max_tokens=10, temperature=0.2, stop_sequences="END", stream=True)
    with sb.span("step") as c:
        sb.set_input(c, {"a": 1})
        sb.set_output(c, "done")
    g = spans(mem)
    a = g["chat"].attributes
    assert a["gen_ai.request.max_tokens"] == 10 and a["gen_ai.request.temperature"] == 0.2
    assert tuple(a["gen_ai.request.stop_sequences"]) == ("END",) and a["gen_ai.request.stream"] is True
    assert json.loads(g["step"].attributes["input.value"]) == {"a": 1}
    assert g["step"].attributes["output.value"] == "done"


def test_setters_never_raise_on_non_recording_span():
    sp = trace.INVALID_SPAN
    sb.set_usage(sp, input_tokens=1, finish_reasons=["x"])
    sb.set_content(sp, prompt="p")
    sb.set_documents(sp, ["d"])
    sb.set_request_params(sp, top_k=3)


# --- sampling and should_export --------------------------------------------------


def test_sample_rate_zero_drops_at_head(mem):
    sb.init(exporter=mem, sample_rate=0.0)
    with sb.span("dropped") as sp:
        assert not sp.is_recording()
    assert spans(mem) == {}
    sb.init(exporter=mem, sample_rate=1.0)  # swapped without a new exporter
    with sb.span("kept"):
        pass
    assert "kept" in spans(mem)


def test_sample_rate_ratio_is_deterministic(mem):
    sb.init(exporter=mem, sample_rate=0.5)
    for i in range(200):
        with sb.span(f"s{i}"):
            with sb.span(f"c{i}"):
                pass
    got = spans(mem)
    assert 40 < len(got) // 2 < 160
    for name, sp in got.items():
        if name.startswith("c"):
            assert "s" + name[1:] in got  # a sampled parent keeps its child, and vice versa


def test_sample_rate_validation_and_env():
    with pytest.raises(ValueError):
        sb.init(sample_rate=1.5)
    assert _config.resolve_sampling(None, {"SUPERBASED_SAMPLE_RATE": "0.25"}) == (0.25, True)
    assert _config.resolve_sampling(None, {"OTEL_TRACES_SAMPLER": "traceidratio", "OTEL_TRACES_SAMPLER_ARG": "0.1"}) == (0.1, False)
    assert _config.resolve_sampling(None, {"OTEL_TRACES_SAMPLER": "parentbased_always_off"}) == (0.0, True)
    assert _config.resolve_sampling(None, {"SUPERBASED_SAMPLE_RATE": "bad"}) == (1.0, True)


def test_attached_mode_applies_ratio_at_export(mem):
    host_mem = InMemorySpanExporter()
    host = TracerProvider()
    host.add_span_processor(SimpleSpanProcessor(host_mem))
    trace.set_tracer_provider(host)
    sb.init(exporter=mem, sample_rate=0.0)
    with sb.span("x"):
        pass
    assert spans(mem) == {}
    assert [s.name for s in host_mem.get_finished_spans()] == ["x"]  # the host still sees it
    assert sb.diagnostics()["sampled_out_spans"] == 1


def test_should_export_filters_and_fails_open(mem):
    def keep(span):
        if span.name == "boom":
            raise RuntimeError("bad hook")
        return span.attributes.get("openinference.span.kind") == "LLM"

    sb.init(exporter=mem, should_export=keep)
    with sb.span("chain"):
        pass
    with sb.llm_span("llm"):
        pass
    with sb.span("boom"):
        pass
    assert set(spans(mem)) == {"llm", "boom"}
    d = sb.diagnostics()
    assert d["filtered_spans"] == 1 and d["should_export_errors"] == 1


# --- masking and content rules ----------------------------------------------------


def test_mask_rewrites_content_only(mem):
    def mask(value, key):
        return value.replace("secret", "***") if isinstance(value, str) else value

    sb.init(exporter=mem, mask=mask)
    with sb.llm_span("chat", prompt="my secret") as s:
        s.set_attribute("sbo.user", "secret-user")
        s.add_event("gen_ai.client.inference.operation.details", {"gen_ai.input.messages": "a secret"})
    sp = spans(mem)["chat"]
    assert sp.attributes["input.value"] == "my ***"
    assert sp.attributes["sbo.user"] == "secret-user"  # identity is not content
    assert sp.events[0].attributes["gen_ai.input.messages"] == "a ***"


def test_mask_failure_drops_content_never_the_span(mem):
    def mask(value, key):
        if key == "input.value":
            raise ValueError("nope")
        return None if key == "output.value" else value

    sb.init(exporter=mem, mask=mask)
    with sb.llm_span("chat", prompt="p", system="sys") as s:
        sb.set_content(s, response="r")
    a = spans(mem)["chat"].attributes
    assert "input.value" not in a and "output.value" not in a
    assert a["gen_ai.system_instructions"] == "sys"
    assert a["openinference.span.kind"] == "LLM"
    assert sb.diagnostics()["mask_errors"] == 1


def test_mask_does_not_touch_host_view(mem):
    host_mem = InMemorySpanExporter()
    host = TracerProvider()
    host.add_span_processor(SimpleSpanProcessor(host_mem))
    trace.set_tracer_provider(host)
    sb.init(exporter=mem, mask=lambda v, k: "[masked]")
    with sb.llm_span("chat", prompt="raw"):
        pass
    assert spans(mem)["chat"].attributes["input.value"] == "[masked]"
    assert host_mem.get_finished_spans()[0].attributes["input.value"] == "raw"


def test_capture_off_strips_foreign_content(mem):
    sb.init(exporter=mem, capture_content=False)
    tracer = trace.get_tracer("instrumentor")
    with tracer.start_as_current_span("oi", attributes={"input.value": "x", "llm.input_messages.0.message.content": "y", "llm.input_messages.0.message.role": "user", "llm.model_name": "m"}):
        pass
    a = spans(mem)["oi"].attributes
    assert "input.value" not in a and "llm.input_messages.0.message.content" not in a
    assert a["llm.input_messages.0.message.role"] == "user" and a["llm.model_name"] == "m"


def test_max_content_chars_applies_to_foreign_content(mem):
    sb.init(exporter=mem, max_content_chars=4)
    with trace.get_tracer("i").start_as_current_span("oi", attributes={"output.value": "abcdefgh"}):
        pass
    assert spans(mem)["oi"].attributes["output.value"] == "abcd" + _pipeline.TRUNCATED_MARK


def test_console_exporter_sees_masked_copy(mem):
    sb.init(exporter=mem, mask=lambda v, k: "M")
    with sb.llm_span("chat", prompt="raw"):
        pass
    sp = spans(mem)["chat"]
    assert json.loads(sp.to_json())["attributes"]["input.value"] == "M"


# --- trace context ------------------------------------------------------------------


def test_trace_ids_and_traceparent(mem):
    sb.init(exporter=mem)
    assert sb.get_current_trace_id() == "" and sb.get_traceparent() == ""
    with sb.span("root") as sp:
        tid = sb.get_current_trace_id()
        assert len(tid) == 32 and tid == format(sp.get_span_context().trace_id, "032x")
        assert len(sb.get_current_span_id()) == 16
        tp = sb.get_traceparent()
        assert tp.startswith("00-" + tid + "-")


def test_inject_extract_continue_trace_with_baggage(mem):
    sb.init(exporter=mem)
    with sb.span("caller"):
        with sb.propagate_attributes(user="alice", tags=["a"], metadata={"plan": "pro"}, as_baggage=True):
            headers = sb.inject()
        caller_tid = sb.get_current_trace_id()
    assert "traceparent" in headers and "sbo.user=alice" in headers["baggage"]
    sb._reset_for_tests()
    mem = InMemorySpanExporter()  # the reset shut the first one down
    sb.init(exporter=mem)
    upper = {k.upper(): v for k, v in headers.items()}  # case-insensitive
    with sb.continue_trace(upper):
        with sb.span("callee"):
            assert sb.get_current_attributes()["user"] == "alice"
    callee = spans(mem)["callee"]
    assert format(callee.context.trace_id, "032x") == caller_tid
    assert callee.attributes["sbo.user"] == "alice" and callee.attributes["sbo.metadata.plan"] == "pro"
    assert tuple(callee.attributes["sbo.tags"]) == ("a",)


def test_inject_without_baggage_and_extract_as_context(mem):
    sb.init(exporter=mem)
    with sb.propagate_attributes(user="private"):
        with sb.span("caller"):
            headers = sb.inject({})
    assert "baggage" not in headers
    ctx = sb.extract(headers)
    with sb._tracer().start_as_current_span("child", context=ctx):
        pass
    got = spans(mem)
    assert got["child"].parent.span_id == got["caller"].context.span_id
    assert sb.extract({"traceparent": "garbage"}) is not None
