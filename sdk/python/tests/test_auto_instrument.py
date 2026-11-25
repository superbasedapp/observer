"""init() instruments by itself (plan 3.1, SDKQS-6): the rule table, the
setting, and the no-import check with its first-import hook.

The in-process cases run against a fake framework and a fake instrumentor
written to a temporary directory, so no real framework is needed; one
subprocess case checks the real openai instrumentation when it is installed.
"""

import logging
import os
import subprocess
import sys
import textwrap

import pytest

import superbased_sdk as sb
from superbased_sdk import _instrument as I

FAKE_LIB = """
import os
COUNT = int(os.environ.get("FAKEFW_IMPORTS", "0")) + 1
os.environ["FAKEFW_IMPORTS"] = str(COUNT)
"""

FAKE_INST = """
calls = []

class FakeInstrumentor:
    _instance = None
    host_already = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.on = False
        return cls._instance

    @property
    def _is_instrumented_by_opentelemetry(self):
        return self.on or FakeInstrumentor.host_already

    def _check_dependency_conflicts(self):
        return None

    def instrument(self, **kw):
        import {lib}
        self.on = True
        calls.append(("instrument", kw.get("tracer_provider")))

    def uninstrument(self, **kw):
        self.on = False
        calls.append(("uninstrument", None))
"""


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    """Two fake targets: ``fakefw`` (auto) and ``fakeagents`` (auto=False,
    like openai-agents), each a framework module plus an instrumentor."""
    names = []
    for lib, inst in (("fakefw_lib", "fakefw_inst"), ("fakeagents_lib", "fakeagents_inst")):
        (tmp_path / (lib + ".py")).write_text(FAKE_LIB.replace("FAKEFW", lib.upper()))
        (tmp_path / (inst + ".py")).write_text(FAKE_INST.replace("{lib}", lib))
        names += [lib, inst]
    monkeypatch.syspath_prepend(str(tmp_path))
    targets = (
        I.Target("fakefw", "fakefw_inst", "FakeInstrumentor", "fakefw_lib", "fakefw", "fakefw-inst", distributions=("fakefw",)),
        I.Target(
            "fakeagents", "fakeagents_inst", "FakeInstrumentor", "fakeagents_lib", "fakeagents", "fakeagents-inst",
            auto=False, distributions=("fakeagents",),
        ),
    )
    monkeypatch.setattr(I, "TARGETS", targets)
    monkeypatch.setattr(I, "_BY_NAME", {t.name: t for t in targets})
    monkeypatch.setattr(I, "ALIASES", {"fw": "fakefw"})
    for n in names:
        monkeypatch.delenv(n.upper() + "_IMPORTS", raising=False)
    yield
    I.uninstrument([t.name for t in targets])
    sb._reset_for_tests()
    for n in names:
        sys.modules.pop(n, None)


def inst_module(name="fakefw_inst"):
    __import__(name)
    return sys.modules[name]


# --- the rule table (plan 3.1), one case per row ---------------------------------


@pytest.mark.parametrize(
    "mode, provider_mode, want",
    [
        ("off", "owned", I.NONE),
        ("off", "attached", I.NONE),
        ("list", "attached", I.NAMED),
        ("list", "owned", I.NAMED),
        ("auto", "attached", I.SKIP),
        ("auto", "standalone", I.SKIP),
        ("auto", "owned", I.INSTALLED),
    ],
)
def test_rule_table(mode, provider_mode, want):
    assert I.decide(mode, provider_mode) == want


# --- the setting --------------------------------------------------------------------


@pytest.mark.parametrize(
    "arg, env, want_mode, want_names, want_source",
    [
        (None, None, "auto", (), "default"),
        (None, "off", "off", (), "env"),
        (None, "false", "off", (), "env"),
        (None, "0", "off", (), "env"),
        (None, " NONE ", "off", (), "env"),
        (None, "auto", "auto", (), "env"),
        (None, "openai, LangGraph", "list", ("openai", "langchain"), "env"),
        ("auto", "off", "auto", (), "argument"),
        ("off", "auto", "off", (), "argument"),
        (False, None, "off", (), "argument"),
        (["anthropic", "llama_index"], "off", "list", ("anthropic", "llama-index"), "argument"),
        ([], None, "off", (), "argument"),
        ("openai, anthropic", None, "list", ("openai", "anthropic"), "argument"),
    ],
)
def test_parse_setting(arg, env, want_mode, want_names, want_source):
    s = I.parse_setting(arg, {} if env is None else {"SUPERBASED_INSTRUMENT": env})
    assert (s.mode, s.names, s.source) == (want_mode, want_names, want_source)


def test_unknown_name_in_env_is_ignored_with_a_warning():
    s = I.parse_setting(None, {"SUPERBASED_INSTRUMENT": "openai,nope"})
    assert s.names == ("openai",)
    assert len(s.warnings) == 1 and "'nope'" in s.warnings[0]


def test_unknown_name_in_the_argument_raises():
    with pytest.raises(ValueError):
        I.parse_setting(["nope"], {})


def test_init_never_fails_on_an_unknown_env_name(fakes, mem, monkeypatch, caplog):
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "fw,nope")
    with caplog.at_level(logging.WARNING, logger="superbased_sdk"):
        sb.init(exporter=mem)
    assert sb.diagnostics()["instrumented"] == {"fakefw": I.PENDING}
    assert any("'nope'" in r.getMessage() for r in caplog.records)


# --- owned: every installed target, no import at check time -----------------------------


def test_auto_owned_hooks_and_instruments_on_first_import(fakes, mem, monkeypatch):
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    d = sb.diagnostics()
    assert d["mode"] == "owned"
    assert d["instrumented"] == {"fakefw": I.PENDING, "fakeagents": I.AUTO_EXCLUDED}
    assert "fakefw_lib" not in sys.modules, "the check imported the framework"
    assert "fakefw_inst" not in sys.modules, "the check imported the instrumentor"
    assert I.pending() == ["fakefw"]

    import fakefw_lib  # noqa: F401 - the app's first import

    assert sb.diagnostics()["instrumented"]["fakefw"] == I.INSTRUMENTED
    assert I.instrumented() == ["fakefw"]
    assert I.pending() == []
    assert I._FINDER not in sys.meta_path
    calls = inst_module().calls
    assert calls == [("instrument", sb._PROVIDER)]
    # The module keeps its real loader.
    assert type(sys.modules["fakefw_lib"].__loader__).__name__ != "_HookLoader"
    # auto_excluded: never instrumented unless named.
    assert inst_module("fakeagents_inst").calls == []


def test_auto_owned_instruments_an_already_imported_framework_now(fakes, mem, monkeypatch):
    import fakefw_lib  # noqa: F401

    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    assert sb.diagnostics()["instrumented"]["fakefw"] == I.INSTRUMENTED
    assert I.pending() == []


def test_explicit_instrument_after_auto_is_already(fakes, mem, monkeypatch):
    import fakefw_lib  # noqa: F401

    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    assert sb.instrument(["fakefw"]) == {"fakefw": I.ALREADY}
    assert len(inst_module().calls) == 1


def test_explicit_instrument_of_a_pending_target_drops_its_hook(fakes, mem, monkeypatch):
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    assert sb.instrument(["fakefw"]) == {"fakefw": I.INSTRUMENTED}
    assert I.pending() == []


def test_host_already_instrumented_is_already(fakes, mem, monkeypatch):
    import fakefw_lib  # noqa: F401

    inst_module().FakeInstrumentor.host_already = True
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    assert sb.diagnostics()["instrumented"]["fakefw"] == I.ALREADY
    assert inst_module().calls == []


def test_named_auto_excluded_target_is_honoured(fakes, mem):
    sb.init(exporter=mem, instrument=["fakeagents"])
    assert sb.diagnostics()["instrumented"] == {"fakeagents": I.PENDING}
    import fakeagents_lib  # noqa: F401

    assert I.instrumented() == ["fakeagents"]


def test_list_with_an_alias_instruments_exactly_those(fakes, mem):
    sb.init(exporter=mem, instrument=["fw"])
    assert sb.diagnostics()["instrumented"] == {"fakefw": I.PENDING}


def test_list_reports_a_missing_target(fakes, mem, monkeypatch):
    monkeypatch.setattr(I, "installed", lambda t: False)
    sb.init(exporter=mem, instrument=["fakefw"])
    assert sb.diagnostics()["instrumented"] == {"fakefw": I.NOT_INSTALLED}


def test_argument_beats_env(fakes, mem, monkeypatch):
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem, instrument="off")
    d = sb.diagnostics()
    assert (d["instrument"], d["instrumented"]) == ("off", {})
    assert I.pending() == []


def test_off_instruments_nothing(fakes, mem, monkeypatch):
    import fakefw_lib  # noqa: F401

    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "off")
    sb.init(exporter=mem)
    assert I.instrumented() == [] and I.pending() == []


# --- a provider the app owns: nothing, one INFO note -----------------------------------


def test_auto_attached_skips_with_one_note(fakes, mem, monkeypatch, caplog):
    import fakefw_lib  # noqa: F401
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    trace.set_tracer_provider(TracerProvider())
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    with caplog.at_level(logging.INFO, logger="superbased_sdk"):
        sb.init(exporter=mem)
        sb.init(exporter=mem, user="again")
    d = sb.diagnostics()
    assert d["mode"] == "attached"
    assert I.action() == I.SKIP
    assert d["instrumented"] == {"fakefw": I.SKIPPED_HOST_PROVIDER, "fakeagents": I.SKIPPED_HOST_PROVIDER}
    assert I.instrumented() == [] and I.pending() == []
    notes = [r for r in caplog.records if "auto-instrumentation skipped" in r.getMessage()]
    assert len(notes) == 1 and notes[0].levelno == logging.INFO


def test_auto_standalone_skips(fakes, mem, monkeypatch):
    from opentelemetry import trace

    class HostProvider(trace.NoOpTracerProvider):
        pass

    trace.set_tracer_provider(HostProvider())
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    d = sb.diagnostics()
    assert d["mode"] == "standalone"
    assert I.action() == I.SKIP and d["instrumented"]["fakefw"] == I.SKIPPED_HOST_PROVIDER
    assert I.pending() == []


def test_a_named_list_applies_under_a_host_provider(fakes, mem):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    trace.set_tracer_provider(TracerProvider())
    sb.init(exporter=mem, instrument=["fakefw"])
    assert sb.diagnostics()["instrumented"] == {"fakefw": I.PENDING}


# --- undo ------------------------------------------------------------------------------


def test_uninstrument_removes_pending_hooks(fakes, mem, monkeypatch):
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    sb.uninstrument()
    assert I.pending() == [] and I._FINDER not in sys.meta_path
    import fakefw_lib  # noqa: F401

    assert I.instrumented() == []
    assert inst_module().calls == []


def test_reinit_off_undoes_what_auto_did(fakes, mem, monkeypatch):
    import fakefw_lib  # noqa: F401

    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)
    assert I.instrumented() == ["fakefw"]
    sb.init(exporter=mem, instrument="off")
    assert I.instrumented() == []
    assert inst_module().calls[-1] == ("uninstrument", None)


def test_reinit_off_keeps_an_explicit_instrument(fakes, mem):
    import fakefw_lib  # noqa: F401

    sb.init(exporter=mem)
    sb.instrument(["fakefw"])
    sb.init(exporter=mem, instrument="off", user="u")
    assert I.instrumented() == ["fakefw"]
    sb.uninstrument()


def test_the_hook_never_breaks_the_import(fakes, mem, monkeypatch):
    monkeypatch.setenv("SUPERBASED_INSTRUMENT", "auto")
    sb.init(exporter=mem)

    def boom(name, provider):
        raise RuntimeError("instrumentor bug")

    monkeypatch.setattr(I, "_instrument_one", boom)
    import fakefw_lib

    assert fakefw_lib.COUNT == 1


def test_findable_does_not_import(fakes):
    assert I.findable("fakefw_lib") and "fakefw_lib" not in sys.modules
    assert not I.findable("no_such_framework_here")
    assert not I.findable("fakefw_lib.sub")
    assert I.findable("os.path")


def test_every_real_target_has_distributions_and_openai_agents_is_named_only():
    for t in I.TARGETS:
        assert t.distributions, t.name
    assert [t.name for t in I.TARGETS if not t.auto] == ["openai-agents"]


# --- the real openai instrumentation, in a fresh process ---------------------------------


def test_real_openai_is_instrumented_on_its_first_import(tmp_path):
    if not I.installed(next(t for t in I.TARGETS if t.name == "openai")):
        pytest.skip("openai or its OpenInference instrumentor not installed")
    code = textwrap.dedent(
        """
        import sys
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        import superbased_sdk as sb
        sb.init(exporter=InMemorySpanExporter(), destination="local")
        targets = sb.diagnostics()["instrumented"]
        assert "openai" not in sys.modules, "init imported openai"
        assert targets["openai"] == "pending", targets
        assert targets.get("openai-agents") in ("skipped: auto_excluded", "skipped: not_installed"), targets
        import openai
        assert sb.diagnostics()["instrumented"]["openai"] == "instrumented"
        from openinference.instrumentation.openai import OpenAIInstrumentor
        assert OpenAIInstrumentor()._is_instrumented_by_opentelemetry
        print("ok")
        """
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SUPERBASED_", "OTEL_"))}
    env.update({"SUPERBASED_DISCOVER": "0", "SUPERBASED_CREDENTIAL_FILE": str(tmp_path / "none"), "SUPERBASED_FIRST_TRACE_LINK": "0"})
    root = os.path.join(os.path.dirname(__file__), "..")
    out = subprocess.run([sys.executable, "-c", code], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=120,
                         check=False)
    env_path = os.pathsep.join([os.path.abspath(root)] + [p for p in sys.path if p])
    if out.returncode != 0 and "No module named 'superbased_sdk'" in out.stderr:
        env["PYTHONPATH"] = env_path
        out = subprocess.run([sys.executable, "-c", code], env=env, cwd=str(tmp_path), capture_output=True, text=True, timeout=120,
                             check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"
