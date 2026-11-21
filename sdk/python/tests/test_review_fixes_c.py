"""Batch C review fixes owned by lane CF-C: R-C04 (the release gate), R-C09
(the key on admit() and on OTEL endpoints), R-C08 (admit identity), R-C31
(an unscored experiment) and R-C35 / R-C36 (public docs and READMEs)."""

import os
import re

import pytest

# The repository root: SUPERBASED_REPO_ROOT when the tests run from a copy of
# the package (scripts/ci/sdk.sh), else three levels up from this file.
ROOT = os.environ.get("SUPERBASED_REPO_ROOT") or os.path.join(os.path.dirname(__file__), "..", "..", "..")


def _read(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        pytest.skip(f"{rel} not present (an sdist)")
    with open(path, encoding="utf-8") as f:
        return f.read()


def _job(workflow, name):
    """The text of one top-level job (two-space indented key) in a workflow."""
    m = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow, re.M | re.S)
    assert m, f"job {name} missing"
    return m.group(1)


def test_rc04_pack_needs_the_gate_attestation_and_e2e():
    wf = _read(".github/workflows/sdk-release.yml")
    e2e = _job(wf, "e2e")
    assert "go run ./tests/sdke2e" in e2e
    assert "if:" not in e2e.split("steps:")[0], "the e2e job is never skipped"
    pack = _job(wf, "pack")
    needs = re.search(r"^    needs: \[(.*?)\]", pack, re.M).group(1)
    assert {n.strip() for n in needs.split(",")} >= {"gate", "verify", "e2e"}
    assert "needs.e2e.result == 'success'" in pack
    assert "needs.gate.outputs.attested" in pack and '!= "true"' in pack and "exit 1" in pack
    for pub in ("publish-pypi", "publish-npm"):
        assert re.search(r"needs: \[gate, pack\]", _job(wf, pub)), pub
        assert "needs.pack.result == 'success'" in _job(wf, pub)


@pytest.mark.parametrize("rel", ["sdk/python/README.md", "sdk/typescript/README.md", "sdk/widget/README.md"])
def test_rc36_package_readmes_link_only_to_public_pages(rel):
    """The package READMEs ship to PyPI and npm: no link into the private
    docs/ tree, no plan path."""
    text = _read(rel)
    assert "../docs/" not in text and "docs/plans" not in text and "`docs/" not in text, rel


def _sdk_docs():
    root = os.path.join(ROOT, "docs", "sdk")
    if not os.path.isdir(root):
        pytest.skip("docs/sdk not present (an sdist)")
    for d, _, fs in os.walk(root):
        for f in fs:
            if f.endswith(".md"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    yield os.path.relpath(os.path.join(d, f), ROOT), fh.read()


def test_rc35_public_docs_name_no_internal_path_or_record_id():
    bad = re.compile(r"internal/[a-z]|docs/plans|\bR-[ABC]\d\d\b|\bD\d\d?\b ruling|\blane [A-C]\d+\b")
    for rel, text in _sdk_docs():
        assert not bad.search(text), (rel, bad.search(text).group(0))
    assert not bad.search(_read("website/pages-src/sdk.html"))


def test_rc35_the_published_ci_credential_command_uses_real_flags():
    text = _read("docs/sdk/python/scores-and-experiments.md")
    cli = _read("cmd/observer-org/ingest_credential.go")
    flags = set(re.findall(r'Flags\(\)\.\w+Var\(&\w+, "([a-z-]+)"', cli))
    for cmd in re.findall(r"observer-org (?:new-service-account|new-ingest-credential)[^\n]*(?:\\\n[^\n]*)*", text):
        for flag in re.findall(r"--([a-z-]+)", cmd):
            assert flag in flags, (flag, cmd)
    assert "--signals none" not in text


def test_rc35_the_node_floor_matches_the_package():
    import json

    engines = json.loads(_read("sdk/typescript/package.json"))["engines"]["node"]
    floor = re.match(r">=(\d+)\.(\d+)", engines).group(1, 2)
    want = f"Node {floor[0]}.{floor[1]} to"
    assert want in _read("website/pages-src/sdk.html")
    assert want in _read("docs/sdk/README.md")


def test_rc35_degraded_online_is_described_as_no_target():
    text = _read("docs/sdk/python/destinations.md")
    assert "Only `admit()`\nfalls back to this machine" in text or "Only `admit()` falls back" in text.replace("\n", " ")
    assert "(when it\nis usable), else this machine" not in text
