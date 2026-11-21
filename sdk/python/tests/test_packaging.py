"""W2-4: the package metadata agrees with the code (version, licence, typing,
one extra per instrument() target)."""

import os
import re

import superbased_sdk as sb
from superbased_sdk import _instrument

ROOT = os.path.join(os.path.dirname(__file__), "..")


def pyproject():
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
        return f.read()


def test_version_matches_pyproject():
    m = re.search(r'^version = "([^"]+)"', pyproject(), re.M)
    assert m and m.group(1) == sb.__version__
    # PEP 440, and a semver core (MAJOR.MINOR.PATCH) the policy relies on.
    assert re.fullmatch(r"\d+\.\d+\.\d+((a|b|rc)\d+)?(\.dev\d+)?", sb.__version__)


def test_licence_and_typing_ship():
    text = pyproject()
    assert 'license = "Apache-2.0"' in text and 'license-files = ["LICENSE", "NOTICE"]' in text
    with open(os.path.join(ROOT, "LICENSE"), encoding="utf-8") as f:
        lic = f.read()
    assert "Apache License" in lic and "END OF TERMS AND CONDITIONS" in lic  # the full text
    assert os.path.exists(os.path.join(ROOT, "NOTICE"))
    assert os.path.exists(os.path.join(ROOT, "superbased_sdk", "py.typed"))
    for v in ("3.9", "3.10", "3.11", "3.12", "3.13"):
        assert f'"Programming Language :: Python :: {v}"' in text
    assert 'requires-python = ">=3.9"' in text


def test_every_instrument_target_has_an_extra():
    text = pyproject()
    for t in _instrument.TARGETS:
        assert re.search(rf'^{re.escape(t.extra)} = \[\s*"{re.escape(t.package)}', text, re.M), t.name
        assert t.package in text.split("all = [", 1)[1].split("]", 1)[0], f"{t.name} missing from the all extra"


def test_public_api_is_exported():
    for name in sb.__all__:
        assert hasattr(sb, name), name
