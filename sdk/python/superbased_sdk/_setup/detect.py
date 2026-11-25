"""Phase 1, detect (plan 3.5): the language, the package manager, the
model libraries, the install command and the entry candidates.

``detect()`` is pure over a ``ProjectView`` (the manifest and lock-file
texts, the project interpreter's installed distributions, the tools on
PATH). The model libraries come from ``_instrument.TARGETS``' own
``distributions`` column (one owner: a new framework is one row there, and
both ``instrument()`` and setup follow it). ``gather()`` is the I/O that
builds the view.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .. import _instrument

PACKAGE = "superbased-sdk"

PYTHON = "python"
NODE = "typescript"  # a package.json project: `npx @superbased/sdk setup`
GO = "go"
JAVA = "java"

# Files read for detection (relative to the project root), at most this many bytes each.
MANIFESTS = (
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements.in",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "package.json",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
)
MAX_MANIFEST_BYTES = 4 << 20

# (language, any of these files) walked top-down: a Python backend with a
# package.json for its front end is a Python project.
LANGUAGE_ROWS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (PYTHON, ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements.in", "Pipfile", "uv.lock", "poetry.lock", "pdm.lock")),
    (NODE, ("package.json",)),
    (GO, ("go.mod",)),
    (JAVA, ("pom.xml", "build.gradle", "build.gradle.kts")),
)

# (manager, rule) walked top-down, first match (setup-cases.json detection):
# uv.lock -> uv; poetry.lock or a [tool.poetry] table -> poetry; pdm.lock ->
# pdm; Pipfile -> pipenv; else pip in the project interpreter.
MANAGER_ROWS: Tuple[Tuple[str, str, str], ...] = (
    ("uv", "file", "uv.lock"),
    ("poetry", "file", "poetry.lock"),
    ("poetry", "table", "tool.poetry"),
    ("pdm", "file", "pdm.lock"),
    ("pipenv", "file", "Pipfile"),
    ("pipenv", "file", "Pipfile.lock"),
    ("pip", "always", ""),
)

# How each manager adds a dependency (the spec is appended).
INSTALL_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "uv": ("uv", "add"),
    "poetry": ("poetry", "add"),
    "pdm": ("pdm", "add"),
    "pipenv": ("pipenv", "install"),
    "pip": ("{python}", "-m", "pip", "install"),
}

# Where an app usually starts, in the order setup names them.
ENTRY_CANDIDATES = (
    "main.py",
    "app.py",
    "server.py",
    "bot.py",
    "agent.py",
    "run.py",
    "api.py",
    "manage.py",
    "asgi.py",
    "wsgi.py",
    "src/main.py",
    "src/app.py",
    "app/main.py",
)

BEDROCK_MARK = "bedrock-runtime"


@dataclass(frozen=True)
class ProjectView:
    """What detection reads: ``files`` maps a manifest's relative path to
    its text (absent: not there); ``installed`` the project interpreter's
    distributions; ``tools`` the package managers on PATH;
    ``bedrock_in_source`` whether the source names ``bedrock-runtime``;
    ``entries`` the entry candidates that exist; ``python`` the project
    interpreter."""

    files: Mapping[str, str] = field(default_factory=dict)
    installed: Tuple[str, ...] = ()
    tools: Tuple[str, ...] = ()
    bedrock_in_source: bool = False
    entries: Tuple[str, ...] = ()
    python: str = "python3"


@dataclass(frozen=True)
class Detection:
    language: str = ""
    package_manager: str = ""
    targets: Tuple[str, ...] = ()  # the model libraries the app uses
    extras: Tuple[str, ...] = ()  # the extras setup installs (auto-instrumented targets)
    named_only: Tuple[str, ...] = ()  # detected, instrumented only when named (openai-agents)
    install: Tuple[str, ...] = ()  # the install command
    entries: Tuple[str, ...] = ()
    tool_missing: str = ""  # the manager's tool is not on PATH


def normalize(name: str) -> str:
    """A distribution name as PEP 503 compares it."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def language(files: Mapping[str, str], has_py_files: bool = False) -> str:
    for lang, markers in LANGUAGE_ROWS:
        if any(m in files for m in markers):
            return lang
    return PYTHON if has_py_files else ""


def _tables(pyproject: str) -> List[str]:
    out = []
    for line in pyproject.splitlines():
        m = re.match(r"^\s*\[\s*([A-Za-z0-9_.\-]+)\s*\]", line)
        if m:
            out.append(m.group(1))
    return out


def manager(view: ProjectView) -> str:
    tables = _tables(view.files.get("pyproject.toml", ""))
    for name, kind, arg in MANAGER_ROWS:
        if kind == "file" and arg in view.files:
            return name
        if kind == "table" and any(t == arg or t.startswith(arg + ".") for t in tables):
            return name
        if kind == "always":
            return name
    return "pip"


def _mentions(text: str, dist: str) -> bool:
    """``dist`` named as a distribution in a manifest or lock file (``-``,
    ``_`` and ``.`` read alike; never a longer name that contains it)."""
    parts = [re.escape(p) for p in re.split(r"[-_.]", dist)]
    pat = r"(?<![A-Za-z0-9_.\-])" + r"[-_.]".join(parts) + r"(?![A-Za-z0-9_\-])"
    return re.search(pat, text, re.IGNORECASE) is not None


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_KEY_NAME = re.compile(r"""^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=""")


def _requirement_name(line: str) -> str:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return ""
    m = _REQ_NAME.match(line)
    return normalize(m.group(1)) if m else ""


def _pyproject_names(text: str) -> Tuple[set, bool]:
    """(names, parsed): ``[project] dependencies`` and the keys of
    ``[tool.poetry.dependencies]``; parsed is False without ``tomllib``
    (3.9, 3.10) or when the file does not parse."""
    try:
        import tomllib  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        return set(), False
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, TypeError):
        return set(), False

    def table(v: object) -> dict:
        return v if isinstance(v, dict) else {}

    names = set()
    deps = table(doc.get("project")).get("dependencies")
    for d in deps if isinstance(deps, list) else ():
        if isinstance(d, str):
            n = _requirement_name(d)
            if n:
                names.add(n)
    for k in table(table(table(doc.get("tool")).get("poetry")).get("dependencies")):
        names.add(normalize(str(k)))
    return names, True


def _table_keys(text: str, tables: Tuple[str, ...]) -> set:
    """The keys of the named tables of a TOML-like file (Pipfile), read line by line."""
    names = set()
    current = ""
    for line in text.splitlines():
        m = re.match(r"^\s*\[\s*([A-Za-z0-9_.\-]+)\s*\]", line)
        if m:
            current = m.group(1)
            continue
        if current in tables:
            k = _KEY_NAME.match(line)
            if k:
                names.add(normalize(k.group(1)))
    return names


def requirement_names(view: ProjectView) -> set:
    """The distributions the project's manifests name: ``[project]
    dependencies`` and ``[tool.poetry.dependencies]`` of pyproject.toml,
    every ``requirements*.txt`` and the Pipfile's packages (a lock file's
    content is not read)."""
    names = set()
    pyproject = view.files.get("pyproject.toml")
    if pyproject is not None:
        got, parsed = _pyproject_names(pyproject)
        if parsed:
            names |= got
        else:  # no tomllib: any known name the file mentions
            known = {normalize(d) for t in _instrument.TARGETS for d in t.distributions}
            names |= {d for d in known if _mentions(pyproject, d)}
    for rel, text in view.files.items():
        if re.fullmatch(r"requirements[^/]*\.(txt|in)", rel):
            names |= {n for n in (_requirement_name(line) for line in text.splitlines()) if n}
    if "Pipfile" in view.files:
        names |= _table_keys(view.files["Pipfile"], ("packages", "dev-packages"))
    return names


def used_distributions(view: ProjectView) -> List[str]:
    """The known framework distributions the project uses: from its
    manifests first, then its installed distributions."""
    known = sorted({normalize(d) for t in _instrument.TARGETS for d in t.distributions})
    named = requirement_names(view) | {normalize(d) for d in view.installed}
    return [d for d in known if d in named]


def detect(view: ProjectView, version: str = "") -> Detection:
    """Phase 1 over a project view."""
    lang = language(view.files, bool(view.entries))
    if lang != PYTHON:
        return Detection(language=lang)
    used = set(used_distributions(view))
    targets: List[str] = []
    for t in _instrument.TARGETS:
        hit = any(normalize(d) in used for d in t.distributions)
        if t.name == "bedrock" and hit and not view.bedrock_in_source:
            hit = False  # boto3 alone is not a Bedrock app
        if hit:
            targets.append(t.name)
    by_name = {t.name: t for t in _instrument.TARGETS}
    extras = tuple(sorted({by_name[n].extra for n in targets if by_name[n].auto}))
    named_only = tuple(n for n in targets if not by_name[n].auto)
    mgr = manager(view)
    spec = PACKAGE + (f"[{','.join(extras)}]" if extras else "") + (f">={version}" if version else "")
    cmd = tuple(view.python if part == "{python}" else part for part in INSTALL_COMMANDS[mgr]) + (spec,)
    missing = "" if mgr == "pip" or mgr in view.tools else mgr
    return Detection(
        language=lang,
        package_manager=mgr,
        targets=tuple(targets),
        extras=extras,
        named_only=named_only,
        install=cmd,
        entries=tuple(e for e in ENTRY_CANDIDATES if e in view.entries) + tuple(e for e in view.entries if e not in ENTRY_CANDIDATES),
        tool_missing=missing,
    )


# --- the I/O that builds the view ------------------------------------------------------

Runner = Callable[[Sequence[str], str, float], Tuple[int, str]]


def run(cmd: Sequence[str], cwd: str, timeout: float) -> Tuple[int, str]:
    """(exit code, stdout) of a command; (-1, "") when it cannot run."""
    try:
        out = subprocess.run(list(cmd), cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        return -1, ""
    return out.returncode, out.stdout or ""


SKIP_DIRS = frozenset({".git", ".venv", "venv", "env", ".env", "node_modules", "__pycache__", "site-packages", "dist", "build", ".tox", ".nox", ".mypy_cache"})
MAX_SOURCE_FILES = 2000
MAX_SOURCE_BYTES = 512 * 1024


def _read(path: str, cap: int) -> Optional[str]:
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            raw = f.read(cap + 1)
    except OSError:
        return None
    if len(raw) > cap:
        raw = raw[:cap]
    return raw.decode("utf-8", "replace")


def _source_mentions(root: str, mark: str) -> bool:
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            seen += 1
            if seen > MAX_SOURCE_FILES:
                return False
            text = _read(os.path.join(dirpath, name), MAX_SOURCE_BYTES)
            if text and mark in text:
                return True
    return False


def project_python(root: str, mgr: str, runner: Runner = run) -> str:
    """The project's interpreter: its ``.venv`` (or ``venv``), the manager's
    own environment, the interpreter running setup when it lives inside the
    project, else ``python3`` (``python`` on Windows) on PATH."""
    for d in (".venv", "venv"):
        for rel in (("bin", "python"), ("Scripts", "python.exe")):
            cand = os.path.join(root, d, *rel)
            if os.path.isfile(cand):
                return cand
    queries = {
        "poetry": (["poetry", "env", "info", "-p"], ("bin/python", "Scripts/python.exe")),
        "pdm": (["pdm", "info", "--python"], ("",)),
        "pipenv": (["pipenv", "--py"], ("",)),
    }
    q = queries.get(mgr)
    if q and shutil.which(q[0][0]):
        code, out = runner(q[0], root, 20.0)
        base = out.strip().splitlines()[-1].strip() if code == 0 and out.strip() else ""
        for suffix in q[1]:
            cand = os.path.join(base, *suffix.split("/")) if suffix else base
            if cand and os.path.isfile(cand):
                return cand
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        here = os.path.abspath(sys.prefix)
        if here.startswith(os.path.abspath(root) + os.sep):
            return sys.executable
    return "python" if os.name == "nt" else "python3"


_LIST_DISTS = (
    "import importlib.metadata as m, json; "
    "print(json.dumps(sorted({(d.metadata['Name'] or '') for d in m.distributions()})))"
)


def installed_distributions(python: str, root: str, runner: Runner = run) -> Tuple[str, ...]:
    code, out = runner([python, "-c", _LIST_DISTS], root, 20.0)
    if code != 0:
        return ()
    try:
        names = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return ()
    return tuple(str(n) for n in names if isinstance(n, str) and n)


def gather(root: str, runner: Runner = run, which: Callable[[str], Optional[str]] = shutil.which) -> ProjectView:
    """Read the project at ``root`` into a ``ProjectView``."""
    files: Dict[str, str] = {}
    for rel in MANIFESTS:
        text = _read(os.path.join(root, rel), MAX_MANIFEST_BYTES)
        if text is not None:
            files[rel] = text
    try:
        for name in sorted(os.listdir(root)):
            if re.fullmatch(r"requirements[^/]*\.(txt|in)", name) and name not in files:
                text = _read(os.path.join(root, name), MAX_MANIFEST_BYTES)
                if text is not None:
                    files[name] = text
    except OSError:
        pass
    tools = tuple(t for t in ("uv", "poetry", "pdm", "pipenv") if which(t))
    entries = tuple(e for e in ENTRY_CANDIDATES if os.path.isfile(os.path.join(root, *e.split("/"))))
    if not entries:
        try:
            entries = tuple(sorted(n for n in os.listdir(root) if n.endswith(".py") and os.path.isfile(os.path.join(root, n))))[:5]
        except OSError:
            entries = ()
    pre = ProjectView(files=files, tools=tools, entries=entries)
    if language(files, bool(entries)) != PYTHON:
        return pre
    mgr = manager(pre)
    python = project_python(root, mgr, runner)
    return ProjectView(
        files=files,
        installed=installed_distributions(python, root, runner),
        tools=tools,
        bedrock_in_source=_source_mentions(root, BEDROCK_MARK),
        entries=entries,
        python=python,
    )
