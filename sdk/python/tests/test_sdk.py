"""Tests for init, spans, observe, content, flush/shutdown and diagnostics."""

import asyncio
import logging
import time

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Status, StatusCode

import superbased_sdk as sb
from superbased_sdk import _config


def spans(mem):
    assert sb.flush(5)
    return {s.name: s for s in mem.get_finished_spans()}


# --- init -----------------------------------------------------------------------


def test_init_registers_provider_with_resource(mem):
    sb.init(exporter=mem, tenant="t1", user="u1", session_id="s1", service_name="svc")
    with sb.span("root"):
        pass
    sp = spans(mem)["root"]
    res = sp.resource.attributes
    assert res["service.name"] == "svc"
    assert res["sbo.tenant"] == "t1" and res["sbo.user"] == "u1" and res["session.id"] == "s1"
    assert res["sbo.sdk"] == "superbased-python"
    assert sb.diagnostics()["mode"] == "owned"
    assert isinstance(trace.get_tracer_provider(), TracerProvider)


def test_double_init_same_settings_is_noop(mem):
    sb.init(exporter=mem)
    proc = sb._PROCESSOR
    delegate = proc.delegate
    sb.init(exporter=mem)
    assert sb._PROCESSOR is proc and proc.delegate is delegate
    with sb.span("once"):
        pass
    assert sb.flush(5)
    assert [s.name for s in mem.get_finished_spans()] == ["once"]  # exported exactly once


def test_reinit_with_new_settings_swaps_exporter_not_processor(mem):
    sb.init(exporter=mem)
    provider = sb._PROVIDER
    n_procs = len(provider._active_span_processor._span_processors)
    other = InMemorySpanExporter()
    sb.init(exporter=other, session_id="s2")
    assert sb._PROVIDER is provider
    assert len(provider._active_span_processor._span_processors) == n_procs
    with sb.span("after"):
        pass
    sb.flush(5)
    assert [s.name for s in other.get_finished_spans()] == ["after"]
    assert mem.get_finished_spans() == ()
    # New identity not on the resource is stamped onto the span.
    assert other.get_finished_spans()[0].attributes["session.id"] == "s2"


def test_init_attaches_to_existing_sdk_provider(mem):
    host_mem = InMemorySpanExporter()
    host = TracerProvider()
    host.add_span_processor(SimpleSpanProcessor(host_mem))
    trace.set_tracer_provider(host)

    sb.init(exporter=mem, user="alice")
    assert sb.diagnostics()["mode"] == "attached"
    host_tracer = trace.get_tracer("host")
    with host_tracer.start_as_current_span("host-span"):
        with sb.span("sdk-span"):
            pass
    got = spans(mem)
    # Both the host's and the SDK's spans reach the SDK exporter, in one trace.
    assert set(got) == {"host-span", "sdk-span"}
    assert got["sdk-span"].context.trace_id == got["host-span"].context.trace_id
    assert got["sdk-span"].attributes["sbo.user"] == "alice"
    # The host's own pipeline still sees them too.
    assert {s.name for s in host_mem.get_finished_spans()} == {"host-span", "sdk-span"}
    # Shutdown flushes the SDK's processor and leaves the host provider alive.
    assert sb.shutdown(5)
    with host_tracer.start_as_current_span("later"):
        pass
    assert "later" in {s.name for s in host_mem.get_finished_spans()}


def test_init_explicit_tracer_provider(mem):
    host = TracerProvider()
    sb.init(exporter=mem, tracer_provider=host)
    with sb.span("x"):
        pass
    assert "x" in spans(mem)
    assert sb.diagnostics()["mode"] == "attached"


def test_span_before_init_is_a_noop():
    with sb.span("nothing") as sp:
        sp.set_attribute("k", "v")
    assert sb.flush() is True
    assert sb.shutdown() is True


# --- spans ----------------------------------------------------------------------


def test_span_kind_and_ok_status(mem):
    sb.init(exporter=mem)
    with sb.span("tool", kind=sb.TOOL, attributes={"a": 1}):
        pass
    sp = spans(mem)["tool"]
    assert sp.attributes["openinference.span.kind"] == "TOOL"
    assert sp.attributes["a"] == 1
    assert sp.status.status_code == StatusCode.OK


def test_span_error_records_exception_once(mem):
    sb.init(exporter=mem)
    with pytest.raises(ValueError):
        with sb.span("boom"):
            raise ValueError("bad")
    sp = spans(mem)["boom"]
    assert sp.status.status_code == StatusCode.ERROR
    assert [e.name for e in sp.events] == ["exception"]


def test_user_error_status_is_not_overwritten(mem):
    sb.init(exporter=mem)
    with sb.span("handled") as sp:
        sp.set_status(Status(StatusCode.ERROR, "model refused"))
    got = spans(mem)["handled"]
    assert got.status.status_code == StatusCode.ERROR
    assert got.status.description == "model refused"


def test_llm_span_emits_genai_and_openinference_keys(mem):
    sb.init(exporter=mem)
    with sb.llm_span("chat", model="gpt-4o", provider="openai", prompt="hi") as s:
        sb.set_usage(s, input_tokens=12, output_tokens=3, response_id="chatcmpl-x", response="yo",
                     response_model="gpt-4o-2024", cost_usd=0.01, request_id="r1")
    a = spans(mem)["chat"].attributes
    assert a["openinference.span.kind"] == "LLM"
    assert a["gen_ai.operation.name"] == "chat"
    assert a["gen_ai.provider.name"] == "openai"
    assert a["gen_ai.system"] == "openai"
    assert a["gen_ai.request.model"] == "gpt-4o" and a["llm.model_name"] == "gpt-4o"
    assert a["llm.provider"] == "openai"
    assert a["gen_ai.usage.input_tokens"] == 12 and a["gen_ai.usage.output_tokens"] == 3
    assert a["gen_ai.response.id"] == "chatcmpl-x"
    assert a["gen_ai.response.model"] == "gpt-4o-2024"
    assert a["gen_ai.usage.cost"] == 0.01 and a["request_id"] == "r1"
    assert a["input.value"] == "hi" and a["output.value"] == "yo"


def test_llm_span_operation_override(mem):
    sb.init(exporter=mem)
    with sb.llm_span("emb", model="m", operation="embeddings"):
        pass
    assert spans(mem)["emb"].attributes["gen_ai.operation.name"] == "embeddings"


# --- content --------------------------------------------------------------------


def test_capture_off_keeps_usage(mem):
    sb.init(exporter=mem, capture_content=False)
    with sb.llm_span("chat", prompt="secret") as s:
        sb.set_usage(s, input_tokens=5, prompt="secret", response="secret")
    a = spans(mem)["chat"].attributes
    assert a["gen_ai.usage.input_tokens"] == 5
    assert "input.value" not in a and "output.value" not in a


def test_capture_env_new_and_legacy(monkeypatch, mem):
    monkeypatch.setenv("SUPERBASED_CAPTURE_CONTENT", "0")
    assert sb.init(exporter=mem).capture_content is False
    monkeypatch.delenv("SUPERBASED_CAPTURE_CONTENT")
    monkeypatch.setenv("OBSERVER_CAPTURE_CONTENT", "off")
    assert sb.init(exporter=mem).capture_content is False
    monkeypatch.setenv("SUPERBASED_CAPTURE_CONTENT", "1")
    assert sb.init(exporter=mem).capture_content is True  # new name wins


def test_tool_content_and_truncation(mem):
    sb.init(exporter=mem, max_content_chars=5)
    with sb.span("t", kind=sb.TOOL) as s:
        sb.set_content(s, tool_args="abcdefghij", tool_result="ok")
    a = spans(mem)["t"].attributes
    assert a["gen_ai.tool.call.arguments"] == "abcde…[truncated]"
    assert a["gen_ai.tool.call.result"] == "ok"


# --- observe --------------------------------------------------------------------


def test_observe_sync_bare_and_named(mem):
    sb.init(exporter=mem)

    @sb.observe
    def plain(x):
        return x + 1

    @sb.observe("named", kind=sb.TOOL)
    def other():
        return "ok"

    assert plain(1) == 2 and other() == "ok"
    got = spans(mem)
    assert "test_observe_sync_bare_and_named.<locals>.plain" in got
    assert got["named"].attributes["openinference.span.kind"] == "TOOL"


def test_observe_async_timing_and_error(mem):
    sb.init(exporter=mem)

    @sb.observe("slow")
    async def slow():
        await asyncio.sleep(0.05)
        return 7

    @sb.observe("fails")
    async def fails():
        await asyncio.sleep(0)
        raise KeyError("k")

    assert asyncio.run(slow()) == 7
    with pytest.raises(KeyError):
        asyncio.run(fails())
    got = spans(mem)
    assert (got["slow"].end_time - got["slow"].start_time) >= 40_000_000  # >= 40 ms
    assert got["slow"].status.status_code == StatusCode.OK
    assert got["fails"].status.status_code == StatusCode.ERROR
    assert len(got["fails"].events) == 1


def test_observe_generator_covers_iteration_and_children(mem):
    sb.init(exporter=mem)

    @sb.observe("gen")
    def gen(n):
        for i in range(n):
            with sb.span(f"child{i}"):
                time.sleep(0.01)
            yield i
        return "done"

    g = gen(3)
    out = []
    # The span is not current while the consumer holds control.
    for v in g:
        out.append(v)
        assert not trace.get_current_span().is_recording()
    assert out == [0, 1, 2]
    got = spans(mem)
    root = got["gen"]
    assert root.status.status_code == StatusCode.OK
    assert (root.end_time - root.start_time) >= 25_000_000
    for i in range(3):
        assert got[f"child{i}"].parent.span_id == root.context.span_id


def test_observe_generator_return_send_throw_close(mem):
    sb.init(exporter=mem)

    @sb.observe("echo")
    def echo():
        got = yield "ready"
        try:
            yield got * 2
        except ValueError:
            yield "handled"
        return "end"

    g = echo()
    assert next(g) == "ready"
    assert g.send(21) == 42
    assert g.throw(ValueError("x")) == "handled"
    with pytest.raises(StopIteration) as stop:
        next(g)
    assert stop.value.value == "end"

    @sb.observe("closed")
    def forever():
        while True:
            yield 1

    f = forever()
    next(f)
    f.close()

    @sb.observe("gen-err")
    def bad():
        yield 1
        raise RuntimeError("late")

    b = bad()
    next(b)
    with pytest.raises(RuntimeError):
        next(b)
    got = spans(mem)
    assert got["echo"].status.status_code == StatusCode.OK
    assert got["closed"].end_time is not None and got["closed"].status.status_code == StatusCode.UNSET
    assert got["gen-err"].status.status_code == StatusCode.ERROR
    assert len(got["gen-err"].events) == 1


def test_observe_async_generator(mem):
    sb.init(exporter=mem)

    @sb.observe("agen")
    async def agen(n):
        for i in range(n):
            await asyncio.sleep(0.01)
            yield i

    @sb.observe("agen-err")
    async def agen_err():
        yield 1
        raise ValueError("x")

    async def main():
        out = [v async for v in agen(3)]
        with pytest.raises(ValueError):
            async for _ in agen_err():
                pass
        return out

    assert asyncio.run(main()) == [0, 1, 2]
    got = spans(mem)
    assert got["agen"].status.status_code == StatusCode.OK
    assert (got["agen"].end_time - got["agen"].start_time) >= 25_000_000
    assert got["agen-err"].status.status_code == StatusCode.ERROR
    assert len(got["agen-err"].events) == 1


# --- flush / shutdown / diagnostics --------------------------------------------


def test_flush_and_shutdown_unreachable_endpoint_is_bounded_and_quiet(dead_url, caplog):
    caplog.set_level(logging.DEBUG)
    sb._export.STATS.last_logged_at = 0
    sb.init(endpoint=dead_url + "/v1/traces", shutdown_timeout=0.5)
    with sb.span("lost"):
        pass
    t = time.monotonic()
    sb.flush()
    ok = sb.shutdown()
    assert time.monotonic() - t < 2.0
    assert ok in (True, False)  # never raises
    d = sb.diagnostics()
    assert d["failed_exports"] >= 1 and d["dropped_spans"] >= 1
    assert d["last_error"]
    # No exporter WARN/ERROR in the host's logs; at most one SDK summary line.
    noisy = [r for r in caplog.records if r.name.startswith("opentelemetry") and r.levelno >= logging.WARNING]
    assert noisy == []
    summaries = [r for r in caplog.records if r.name == "superbased_sdk"]
    assert len(summaries) <= 1


def test_failure_log_is_rate_limited(caplog):
    caplog.set_level(logging.WARNING, logger="superbased_sdk")
    st = sb._export.STATS
    st.last_logged_at = 0
    st.unlogged_failures = 3
    now = 1_000_000.0
    assert sb._export.maybe_log_failures(now) is True
    st.unlogged_failures = 1
    assert sb._export.maybe_log_failures(now + 10) is False
    assert sb._export.maybe_log_failures(now + 61) is True
    assert len([r for r in caplog.records if r.name == "superbased_sdk"]) == 2


def test_exporter_exception_is_counted_not_raised():
    class Boom:
        def export(self, spans):
            raise RuntimeError("kaput")

        def shutdown(self):
            raise RuntimeError("kaput")

    sb.init(exporter=Boom())
    with sb.span("x"):
        pass
    sb.flush(5)
    assert sb.shutdown(5) is True
    d = sb.diagnostics()
    assert d["failed_exports"] == 1 and d["dropped_spans"] == 1
    assert "kaput" in d["last_error"]
    assert d["initialized"] is False


def test_shutdown_then_reinit_exports_again(mem):
    sb.init(exporter=mem)
    sb.shutdown(5)
    fresh = InMemorySpanExporter()  # a shut-down exporter refuses further spans
    sb.init(exporter=fresh)
    with sb.span("again"):
        pass
    assert "again" in spans(fresh)
    assert sb.diagnostics()["exported_spans"] >= 1


# --- settings / env -------------------------------------------------------------


def test_endpoint_resolution_order():
    r = _config.resolve_endpoint
    assert r(None, {}) == "http://127.0.0.1:4318/v1/traces"
    assert r(None, {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://gw.example/"}) == "https://gw.example/v1/traces"
    env = {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://a", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://b/t"}
    assert r(None, env) == "https://b/t"
    env["SUPERBASED_OTLP_ENDPOINT"] = "https://c/v1/traces"
    assert r(None, env) == "https://c/v1/traces"
    assert r("https://d", env) == "https://d"


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("OTEL_SERVICE_NAME", "from-otel")
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=prod,service.name=ignored,team=a%20b")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-a=1,x-b=2")
    monkeypatch.setenv("SUPERBASED_OTLP_HEADERS", "x-b=3")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "1500")
    monkeypatch.setenv("SUPERBASED_API_KEY", "k1")
    monkeypatch.setenv("SUPERBASED_TENANT", "acme")
    monkeypatch.setenv("SUPERBASED_SHUTDOWN_TIMEOUT_MS", "750")
    monkeypatch.setenv("SUPERBASED_MAX_CONTENT_CHARS", "0")
    s = _config.Settings.resolve(_config.environ(), headers={"x-c": "4"})
    assert s.service_name == "from-otel"
    assert dict(s.resource_attributes)["team"] == "a b"
    assert dict(s.headers) == {"x-a": "1", "x-b": "3", "x-c": "4"}
    assert s.export_timeout == 1.5 and s.shutdown_timeout == 0.75
    assert s.tenant == "acme" and s.max_content_chars == 0
    d = s.destinations()
    assert len(d) == 1 and dict(d[0].headers)["Authorization"] == "Bearer k1"
    monkeypatch.setenv("SUPERBASED_SERVICE_NAME", "sb")
    assert _config.Settings.resolve(_config.environ()).service_name == "sb"
    assert _config.Settings.resolve(_config.environ(), service_name="arg").service_name == "arg"


def test_service_name_from_resource_attributes(monkeypatch):
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=res-svc")
    assert _config.resolve_service_name(None, _config.environ()) == "res-svc"
    assert _config.resolve_service_name(None, {}) == "custom-app"


def test_otel_resource_attributes_land_on_resource(monkeypatch, mem):
    monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=staging")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "svc-env")
    sb.init(exporter=mem)
    with sb.span("r"):
        pass
    res = spans(mem)["r"].resource.attributes
    assert res["service.name"] == "svc-env"
    assert res["deployment.environment"] == "staging"


def test_unknown_setting_rejected():
    with pytest.raises(TypeError):
        _config.Settings.resolve({}, nope=1)


def test_settings_accessor(mem):
    assert sb.settings() is None
    s = sb.init(exporter=mem, user="u")
    assert sb.settings() is s and s.user == "u"
