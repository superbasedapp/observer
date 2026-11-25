"""The service name from the project (plan 3.2): the ladder, one case per
rung, the normalisation and the reported source."""

import os

import pytest

import superbased_sdk as sb
from superbased_sdk import _config as C

P = C.ProjectFacts
# The real reader, captured at collection (conftest replaces it per test).
REAL_PROJECT_FACTS = C.project_facts


@pytest.mark.parametrize(
    "explicit, env, project, want",
    [
        ("arg-svc", {"SUPERBASED_SERVICE_NAME": "env-svc"}, P("manifest", "/w/dir"), ("arg-svc", "argument")),
        (None, {"SUPERBASED_SERVICE_NAME": "env-svc", "OTEL_SERVICE_NAME": "otel"}, P("manifest"), ("env-svc", "env")),
        (None, {"OTEL_SERVICE_NAME": "otel"}, P("manifest"), ("otel", "env")),
        (None, {"OTEL_RESOURCE_ATTRIBUTES": "service.name=res"}, P("manifest"), ("res", "env")),
        (None, {}, P("Support Bot", "/w/other"), ("support-bot", "manifest")),
        (None, {}, P("", "/home/me/support-bot"), ("support-bot", "entry_dir")),
        (None, {}, P("", "/home/me/support-bot/src"), ("support-bot", "entry_dir")),
        (None, {}, P("", "/home/me/bot/src/app"), ("bot", "entry_dir")),
        (None, {}, P("", "C:\\work\\My Bot\\dist"), ("my-bot", "entry_dir")),
        (None, {}, P("", "/src"), ("custom-app", "default")),
        (None, {}, P("!!!", ""), ("custom-app", "default")),
        (None, {}, P(), ("custom-app", "default")),
    ],
)
def test_ladder(explicit, env, project, want):
    assert C.service_name_ladder(explicit, env, project) == want


@pytest.mark.parametrize(
    "raw, want",
    [
        ("Support Bot", "support-bot"),
        ("acme.Bot_2", "acme.bot_2"),
        ("--weird//name--", "weird-name"),
        ("ünïcode app", "n-code-app"),
        ("x" * 80, "x" * 64),
        ("", ""),
    ],
)
def test_normalisation(raw, want):
    assert C.normalize_service_name(raw) == want


def test_explicit_and_env_values_are_not_normalised():
    assert C.service_name_ladder("My Service", {}, P()) == ("My Service", "argument")
    assert C.service_name_ladder(None, {"OTEL_SERVICE_NAME": "Billing API"}, P()) == ("Billing API", "env")


@pytest.mark.parametrize(
    "text, want",
    [
        ('[project]\nname = "support-bot"\nversion = "1"\n', "support-bot"),
        ("[project]\nname='single'\n", "single"),
        ('[tool.poetry]\nname = "poet"\n', "poet"),
        ('[tool.poetry]\nname = "poet"\n[project]\nname = "pep621"\n', "pep621"),
        ('[tool.ruff]\nname = "not-this"\n', ""),
        ('[[tool.x]]\nname = "array"\n', ""),
        ('[project] # the project\n  name = "spaced"  # comment\n', "spaced"),
    ],
)
def test_manifest_name(text, want):
    assert C.manifest_name(text) == want


def test_find_project_reads_one_file_per_directory_for_at_most_eight(tmp_path):
    reads = []

    def read(path):
        reads.append(path)
        return None

    deep = tmp_path.joinpath(*["d"] * 12)
    deep.mkdir(parents=True)
    assert C.find_project(str(deep), read) == P("", str(deep))
    assert len(reads) == 8
    assert all(os.path.basename(r) == "pyproject.toml" for r in reads)


def test_find_project_takes_the_nearest_manifest(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "outer"\n')
    inner = tmp_path / "svc" / "src"
    inner.mkdir(parents=True)
    (tmp_path / "svc" / "pyproject.toml").write_text('[project]\nname = "inner"\n')
    assert C.find_project(str(inner)).manifest_name == "inner"
    (tmp_path / "svc" / "pyproject.toml").write_text("[tool.ruff]\n")
    # The nearest manifest has no name: that is the answer (the folder rung follows).
    assert C.find_project(str(inner)).manifest_name == ""


def test_entry_directory(tmp_path):
    script = tmp_path / "app" / "main.py"
    script.parent.mkdir()
    script.write_text("")
    prefix = tmp_path / "venv"
    tool = prefix / "bin" / "uvicorn"
    tool.parent.mkdir(parents=True)
    tool.write_text("")
    cwd = str(tmp_path / "work")
    assert C.entry_directory(str(script), cwd, (str(prefix),)) == str(script.parent)
    assert C.entry_directory(str(tool), cwd, (str(prefix),)) == cwd  # an installed console script
    assert C.entry_directory("-c", cwd, ()) == cwd
    assert C.entry_directory("", cwd, ()) == cwd
    assert C.entry_directory(str(tmp_path / "missing.py"), cwd, ()) == cwd


def test_a_bad_project_never_fails_init(mem, monkeypatch):
    def boom():
        raise OSError("unreadable")

    monkeypatch.setattr(C, "project_facts", boom)
    sb.init(exporter=mem, destination="local")
    d = sb.diagnostics()
    assert (d["service_name"], d["service_name_source"]) == ("custom-app", "default")


def test_init_reports_the_rung_and_uses_the_name(mem, monkeypatch):
    monkeypatch.setattr(C, "project_facts", lambda: P("Support Bot", "/w"))
    sb.init(exporter=mem, destination="local")
    d = sb.diagnostics()
    assert (d["service_name"], d["service_name_source"]) == ("support-bot", "manifest")
    with sb.span("x"):
        pass
    sb.flush(5)
    assert mem.get_finished_spans()[-1].resource.attributes["service.name"] == "support-bot"


def test_the_real_process_reads_its_project(tmp_path, monkeypatch):
    """project_facts() itself (unpatched): a script under a project folder."""
    real = REAL_PROJECT_FACTS
    proj = tmp_path / "acme-bot"
    (proj / "src").mkdir(parents=True)
    (proj / "pyproject.toml").write_text('[project]\nname = "acme-bot"\n')
    script = proj / "src" / "main.py"
    script.write_text("")
    monkeypatch.setattr("sys.argv", [str(script)])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert real() == P("acme-bot", str(proj / "src"), str(tmp_path / "home"))


@pytest.mark.parametrize(
    "text, want",
    [
        ('[project]\nname = "support-bot"\nversion = "1"\n', "support-bot"),
        ("[project]\nname='single'\n", "single"),
        ('[tool.poetry]\nname = "poet"\n', "poet"),
        ('[tool.poetry]\nname = "poet"\n[project]\nname = "pep621"\n', "pep621"),
        ('[tool.ruff]\nname = "not-this"\n', ""),
        ('[[tool.x]]\nname = "array"\n', ""),
        ('[project] # the project\n  name = "spaced"  # comment\n', "spaced"),
        ('[project]\nversion = "1"\n', ""),
    ],
)
def test_manifest_name_without_tomllib(text, want):
    """Python 3.9 and 3.10 have no tomllib: the line reader gives the same names."""
    assert C._manifest_name_lines(text) == want
