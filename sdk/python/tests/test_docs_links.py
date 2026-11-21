"""Public SDK docs (docs/sdk) hold together: every relative link names a page
the website publishes, and every page under docs/sdk is published. The
website's /docs generator refuses a relative link to an unpublished page, so
this catches it before a build (E-91)."""

import os
import re

import pytest

ROOT = os.environ.get("SUPERBASED_REPO_ROOT") or os.path.join(os.path.dirname(__file__), "..", "..", "..")
SDK_DOCS = os.path.join(ROOT, "docs", "sdk")
NAV = os.path.join(ROOT, "website", "docs-src", "nav.toml")


def _need(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.relpath(path, ROOT)} not present (an sdist)")


def _pages():
    _need(SDK_DOCS)
    for d, _, fs in os.walk(SDK_DOCS):
        for f in fs:
            if f.endswith(".md"):
                yield os.path.relpath(os.path.join(d, f), SDK_DOCS).replace(os.sep, "/")


def _published():
    _need(NAV)
    with open(NAV, encoding="utf-8") as fh:
        return set(re.findall(r'^\s*file = "sdk:([^"]+)"', fh.read(), re.M))


LINK = re.compile(r"\]\(([^)\s]+)\)")


def test_every_relative_link_names_a_published_page():
    published = _published()
    bad = []
    for rel in _pages():
        with open(os.path.join(SDK_DOCS, rel), encoding="utf-8") as fh:
            text = fh.read()
        for dest in LINK.findall(text):
            if dest.startswith(("#", "/", "mailto:")) or "://" in dest:
                continue
            target = dest.split("#", 1)[0]
            resolved = os.path.normpath(os.path.join(os.path.dirname(rel), target)).replace(os.sep, "/")
            if not target.endswith(".md") or resolved not in published:
                bad.append(f"{rel}: {dest}")
    assert not bad, bad


def test_every_sdk_page_is_published():
    published = _published()
    missing = sorted(p for p in _pages() if p not in published)
    assert not missing, missing


@pytest.mark.parametrize("page", ["keys-and-scopes.md", "admit.md", "ai-gateway.md", "ci-gate.md"])
def test_the_workflow_guides_exist(page):
    """E-65 and E-68: the AI gateway route, admit(), the scope table and the
    CI recipe each have a public page."""
    assert page in _published()
    assert os.path.exists(os.path.join(SDK_DOCS, page))


def test_the_ci_recipe_has_the_prompt_scope():
    """E-68: a CI task that calls get_prompt() needs sdk:read beside sdk:eval."""
    for rel in ("python/scores-and-experiments.md", "keys-and-scopes.md"):
        with open(os.path.join(SDK_DOCS, rel), encoding="utf-8") as fh:
            assert "--sdk-scopes sdk:eval,sdk:read" in fh.read(), rel
    with open(os.path.join(SDK_DOCS, "quickstart-self-host.md"), encoding="utf-8") as fh:
        text = fh.read()
    assert "--sdk-scopes admit\n" not in text and "--sdk-scopes admit " not in text
    assert "keys-and-scopes.md" in text
