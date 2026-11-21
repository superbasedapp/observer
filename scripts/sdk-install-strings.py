#!/usr/bin/env python3
"""Flip the SDK install strings from "not published yet" to the registry
lines when the SDKs are published (review E-66, ruling D29).

Until the first SDK release every surface says the packages are not on PyPI
or npm yet and shows an install from a checkout. On the release day (after
the sdk-v<x.y.z> workflow has published, docs/release-runbook.md "SDK
release") the operator runs:

    python3 scripts/sdk-install-strings.py flip
    make website-build

and commits the result. `check` (the default) verifies that every row below
is wholly in one state, so a surface that changed its wording without this
table failing loudly; `scripts/test_sdk_install_strings.py` runs it.

Each row is (glob relative to the repository root, the pre-release text, the
released text). Every file the glob matches is rewritten; a row must match
at least once.

The SDK catalog (shared/lib/sdkCatalog.json, review P-11, lane C0) is the one
source of the apps' install lines and init snippets: web and web2 read it,
and so does the marketing page generator through its @@sdk.*@@ tokens. Its
rows carry a `published` flag, not text, so the apps need no row here:

- `check` also validates the catalog, requires every row the sdk-release
  workflow publishes (`"release": "sdk-release"`) to be published exactly
  when the text rows are, and fails when an app's source hard-codes a
  catalog install line instead of reading the catalog;
- `flip` also sets `published` on those rows;
- `flip --sdk <id>` marks one row that no workflow publishes yet
  (`"release": "none"`, today Go and Java) as published, on the day its
  package is out, and touches nothing else.

Standard library only.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from typing import Any, Dict, List, NamedTuple


class Row(NamedTuple):
    pattern: str
    before: str
    after: str


ROWS: List[Row] = [
    # The public SDK guides (published on the website by its docs generator).
    Row(
        "docs/sdk/README.md",
        "**Install.** No package is published on PyPI, npm or Maven Central yet.\n"
        "Until the first release, install from a checkout of the\n"
        "[public repository](https://github.com/superbasedapp/observer)\n"
        "(`pip install ./sdk/python`, `npm install ./sdk/typescript`, or\n"
        "`mvn -f sdk/java install` for Java).",
        # The sdk-release workflow publishes PyPI and npm only; Java (Maven
        # Central) and Go (a module tag) have no publish workflow yet, so the
        # released text keeps Java's checkout install. The Go paragraph after
        # it is not a row: it changes when Go is tagged.
        "**Install.** `pip install superbased-sdk` (PyPI) or\n"
        "`npm install @superbased/sdk` (npm); the end-user feedback widget is\n"
        "`npm install @superbased/feedback-widget`. Java is not on Maven Central\n"
        "yet: install it from a checkout of the\n"
        "[public repository](https://github.com/superbasedapp/observer)\n"
        "(`mvn -f sdk/java install`).",
    ),
    Row(
        "docs/sdk/quickstart-machine.md",
        "Not on PyPI or npm yet; from a checkout of the\n"
        "[public repository](https://github.com/superbasedapp/observer):\n"
        "\n"
        "```bash\n"
        "pip install ./sdk/python\n"
        "```\n"
        "\n"
        "```bash\n"
        "npm install ./sdk/typescript\n"
        "```\n"
        "\n"
        "The first TypeScript install also builds the SDK: it fetches the compiler and\n"
        "the OpenTelemetry packages the SDK pins, so it needs network access and takes\n"
        "a little longer than later installs.",
        "```bash\n"
        "pip install superbased-sdk\n"
        "```\n"
        "\n"
        "```bash\n"
        "npm install @superbased/sdk\n"
        "```",
    ),
    Row(
        "docs/sdk/feedback-widget.md",
        "The package is not on npm yet. Until the first release, build it from a\n"
        "checkout of the [public repository](https://github.com/superbasedapp/observer)\n"
        "and copy its `dist/` folder into your app:\n"
        "\n"
        "```bash\n"
        "cd sdk/widget && npm ci && npm run build\n"
        "```",
        "```bash\n"
        "npm install @superbased/feedback-widget\n"
        "```\n"
        "\n"
        "Without a bundler, serve the package's `dist/` folder with your static\n"
        "files (below, under `/vendor/feedback-widget/`).",
    ),
    # The package READMEs (the PyPI and npm project pages).
    Row(
        "sdk/python/README.md",
        "The package is not on PyPI yet. Install from a checkout:\n"
        "\n"
        "```bash\n"
        "pip install -e sdk/python\n"
        "```",
        "```bash\n"
        "pip install superbased-sdk\n"
        "```",
    ),
    Row(
        "sdk/python/README.md",
        'pip install -e "sdk/python[openai]"   # also',
        'pip install "superbased-sdk[openai]"  # also',
    ),
    Row(
        "sdk/typescript/README.md",
        "The package is not on npm yet. Install from a checkout:\n"
        "\n"
        "```bash\n"
        "cd /path/to/your-app && npm install /path/to/sdk/typescript\n"
        "```\n"
        "\n"
        "The first install builds the SDK in place (its `prepare` script): npm does\n"
        "not install a linked folder's development tools, so the script fetches the\n"
        "compiler, the Node types and the OpenTelemetry dependencies at the versions\n"
        "`package-lock.json` pins, without running any package's install scripts. In a\n"
        "development checkout where `npm install` already ran in `sdk/typescript`,\n"
        "nothing is fetched. `npm run test:install` checks this install from a fresh\n"
        "copy (it downloads packages).",
        "```bash\n"
        "npm install @superbased/sdk\n"
        "```",
    ),
    Row(
        "sdk/widget/README.md",
        "The package is not on npm yet. Until the first release, build it from a\n"
        "checkout and copy its `dist/` folder into your app:\n"
        "\n"
        "```bash\n"
        "cd sdk/widget && npm ci && npm run build\n"
        "```",
        "```bash\n"
        "npm install @superbased/feedback-widget\n"
        "```",
    ),
    # The machine dashboard's AI Apps first-run card and the org dashboard's
    # Apps & SDKs facts read the SDK catalog (CATALOG below), not text rows.
    # The examples keep installing the SDK from this checkout (they test the
    # SDK beside them); their notes stop saying it is unpublished.
    Row(
        "examples/ai-apps/README.md",
        "- The SDK from a checkout of this repository (neither package is published yet):",
        "- The SDK from a checkout of this repository, so each example tests the SDK\n"
        "  beside it (in your own app: `pip install superbased-sdk` or\n"
        "  `npm install @superbased/sdk`):",
    ),
    Row(
        "examples/ai-apps/*/*/README.md",
        "The SDK is not on PyPI yet; install it from a",
        "The examples install the SDK from a",
    ),
    Row(
        "examples/ai-apps/*/*/README.md",
        "The SDK is\nnot on PyPI yet, so install it from this checkout.",
        "The examples\ninstall the SDK from this checkout.",
    ),
    Row(
        "examples/ai-apps/*/*/README.md",
        "The SDK is not on npm yet: `package.json` installs it from",
        "The examples test the SDK beside them: `package.json` installs it from",
    ),
    Row(
        "examples/ai-apps/*/*/requirements.txt",
        "# Install the superbased SDK from a checkout first (it is not on PyPI yet):",
        "# Install the superbased SDK from this checkout first (the examples test it):",
    ),
    Row(
        "examples/ai-apps/*/*/requirements.txt",
        "# Install the superbased SDK from this checkout first (README step 2); it is\n# not on PyPI yet.",
        "# Install the superbased SDK from this checkout first (README step 2); the\n# examples test it.",
    ),
    # The marketing pages (rendered by `make website-build`).
    Row(
        "website/pages-src/sdk.html",
        'Neither package is on PyPI or npm yet. Until the first release, install from a checkout of the '
        '<a href="https://github.com/superbasedapp/observer" rel="noopener" data-track="package_outbound" '
        'data-track-channel="github" style="color:var(--accent); border-bottom:1px solid var(--accent);">public repository</a>: '
        "<code>pip install ./sdk/python</code> or <code>npm install ./sdk/typescript</code>.",
        "Install from PyPI or npm: <code>pip install superbased-sdk</code> or <code>npm install @superbased/sdk</code>.",
    ),
    Row("website/pages-src/*.html", "The SDKs are not on PyPI or npm yet.", "The SDKs are on PyPI and npm."),
    Row("website/pages-src/*.html", "the SDKs are not on PyPI or npm yet.", "the SDKs are on PyPI and npm."),
]

PRE, POST = "not published", "published"

# CATALOG is the SDK catalog, relative to the repository root.
CATALOG = "shared/lib/sdkCatalog.json"
# The release values a catalog row may carry: "sdk-release" rows are flipped
# with the text rows; "none" rows only by `flip --sdk <id>`.
RELEASED_BY_WORKFLOW, RELEASED_BY_HAND = "sdk-release", "none"
_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
# APP_SOURCES are the app sources that must read install lines from the
# catalog: a hard-coded catalog install line there is a surface the flip
# would miss.
APP_SOURCES = ("web/src", "web2/src", "webcloud/src")
_APP_EXTS = (".ts", ".tsx")


def _files(root: str, pattern: str) -> List[str]:
    return sorted(glob.glob(os.path.join(root, pattern)))


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def row_state(root: str, row: Row) -> str:
    """PRE, POST, or a sentence saying why the row is in neither."""
    before = after = 0
    for path in _files(root, row.pattern):
        text = _read(path)
        before += text.count(row.before)
        after += text.count(row.after)
    if before and not after:
        return PRE
    if after and not before:
        return POST
    if not before and not after:
        return f"{row.pattern}: neither the pre-release nor the released text is there (the surface changed its wording: update scripts/sdk-install-strings.py)"
    return f"{row.pattern}: both the pre-release and the released text are there"


def load_catalog(root: str) -> Dict[str, Any]:
    """The decoded catalog. Raises ValueError for a malformed one, with the
    rules shared/lib/sdkCatalog.ts parseSdkCatalog applies."""
    path = os.path.join(root, CATALOG)
    try:
        doc = json.loads(_read(path))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{CATALOG}: {exc}") from exc
    sdks = doc.get("sdks") if isinstance(doc, dict) else None
    if not isinstance(sdks, list) or not sdks:
        raise ValueError(f'{CATALOG}: "sdks" must be a non-empty list')
    seen = set()
    for i, row in enumerate(sdks):
        if not isinstance(row, dict):
            raise ValueError(f"{CATALOG}: row {i} is not an object")
        rid = row.get("id")
        if not isinstance(rid, str) or not _ID_RE.match(rid):
            raise ValueError(f"{CATALOG}: row {i}: bad id {rid!r}")
        if rid in seen:
            raise ValueError(f"{CATALOG}: duplicate id {rid!r}")
        seen.add(rid)
        for key in ("label", "package", "registry", "docs", "install_checkout", "install_published"):
            v = row.get(key)
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"{CATALOG}: row {rid!r}: {key!r} must be a non-empty string")
        if "\n" in row["install_checkout"] or "\n" in row["install_published"]:
            raise ValueError(f"{CATALOG}: row {rid!r}: an install line must be one line")
        if row["install_checkout"] == row["install_published"]:
            raise ValueError(f"{CATALOG}: row {rid!r}: the two install lines are the same")
        if not isinstance(row.get("published"), bool):
            raise ValueError(f"{CATALOG}: row {rid!r}: 'published' must be true or false")
        if row.get("release") not in (RELEASED_BY_WORKFLOW, RELEASED_BY_HAND):
            raise ValueError(f"{CATALOG}: row {rid!r}: unknown release {row.get('release')!r}")
        snippet = row.get("snippet")
        if not isinstance(snippet, list) or not snippet or not all(isinstance(x, str) for x in snippet):
            raise ValueError(f"{CATALOG}: row {rid!r}: 'snippet' must be a non-empty list of lines")
    return doc


def write_catalog(root: str, doc: Dict[str, Any]) -> None:
    """Write the catalog back in its committed layout (two-space JSON)."""
    with open(os.path.join(root, CATALOG), "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


def hard_coded_installs(root: str, doc: Dict[str, Any]) -> List[str]:
    """Every "<file>: <id>" where an app source spells a catalog install
    line itself instead of reading the catalog."""
    lines = [(r["id"], r[k]) for r in doc["sdks"] for k in ("install_checkout", "install_published")]
    out: List[str] = []
    for base in APP_SOURCES:
        for dirpath, dirnames, filenames in os.walk(os.path.join(root, base)):
            dirnames[:] = [d for d in dirnames if d != "node_modules"]
            for name in sorted(filenames):
                if not name.endswith(_APP_EXTS):
                    continue
                path = os.path.join(dirpath, name)
                text = _read(path)
                for rid, line in lines:
                    if line in text:
                        out.append(f"{os.path.relpath(path, root)}: {rid}")
    return sorted(set(out))


def catalog_state(root: str) -> str:
    """PRE or POST from the catalog's sdk-release rows, or a sentence
    saying what is wrong with the catalog."""
    try:
        doc = load_catalog(root)
    except ValueError as exc:
        return str(exc)
    hard = hard_coded_installs(root, doc)
    if hard:
        return f"{', '.join(hard)}: an app hard-codes a catalog install line (read shared/lib/sdkCatalog.ts instead)"
    flags = {r["published"] for r in doc["sdks"] if r["release"] == RELEASED_BY_WORKFLOW}
    if flags == {False}:
        return PRE
    if flags == {True}:
        return POST
    if not flags:
        return f"{CATALOG}: no row has release {RELEASED_BY_WORKFLOW!r}"
    return f"{CATALOG}: the {RELEASED_BY_WORKFLOW!r} rows disagree on 'published'"


def _where(i: int) -> str:
    return "the catalog" if i == len(ROWS) else f"row {i}"


def check(root: str) -> Dict[str, List[int]]:
    """{state: [row indexes]} for every row. The catalog counts as one more
    row, index len(ROWS)."""
    out: Dict[str, List[int]] = {}
    for i, row in enumerate(ROWS):
        out.setdefault(row_state(root, row), []).append(i)
    out.setdefault(catalog_state(root), []).append(len(ROWS))
    return out


def flip(root: str) -> List[str]:
    """Rewrite every row from the pre-release to the released text. Refuses
    (ValueError) unless every row is wholly pre-release. Returns the files
    written."""
    states = check(root)
    if set(states) != {PRE}:
        raise ValueError("refusing to flip: " + "; ".join(f"{_where(i)}: {s}" for s, rows in states.items() if s != PRE for i in rows))
    written: List[str] = []
    for row in ROWS:
        for path in _files(root, row.pattern):
            text = _read(path)
            if row.before not in text:
                continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace(row.before, row.after))
            if path not in written:
                written.append(path)
    doc = load_catalog(root)
    for r in doc["sdks"]:
        if r["release"] == RELEASED_BY_WORKFLOW:
            r["published"] = True
    write_catalog(root, doc)
    written.append(os.path.join(root, CATALOG))
    return written


def flip_sdk(root: str, sdk_id: str) -> str:
    """Mark one catalog row that no workflow publishes as published.
    Refuses (ValueError) an unknown id, an sdk-release row (`flip` owns
    those) or a row already published. Returns the file written."""
    doc = load_catalog(root)
    rows = [r for r in doc["sdks"] if r["id"] == sdk_id]
    if not rows:
        raise ValueError(f"no catalog row {sdk_id!r} (known: {', '.join(r['id'] for r in doc['sdks'])})")
    row = rows[0]
    if row["release"] != RELEASED_BY_HAND:
        raise ValueError(f"row {sdk_id!r} is published by the {row['release']} workflow: run `flip` on its release day")
    if row["published"]:
        raise ValueError(f"row {sdk_id!r} is already published")
    row["published"] = True
    write_catalog(root, doc)
    return os.path.join(root, CATALOG)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", nargs="?", default="check", choices=("check", "flip"))
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--sdk", help="with flip: mark only this catalog row (one no workflow publishes) as published")
    args = ap.parse_args(argv)
    if args.sdk and args.mode != "flip":
        ap.error("--sdk goes with flip")
    if args.mode == "flip" and args.sdk:
        try:
            path = flip_sdk(args.root, args.sdk)
        except ValueError as exc:
            print(f"sdk-install-strings: {exc}", file=sys.stderr)
            return 1
        print("rewrote", os.path.relpath(path, args.root))
        print("now run `make website-build` and commit the result")
        return 0
    if args.mode == "flip":
        try:
            written = flip(args.root)
        except ValueError as exc:
            print(f"sdk-install-strings: {exc}", file=sys.stderr)
            return 1
        for p in written:
            print("rewrote", os.path.relpath(p, args.root))
        print("now run `make website-build` and commit the result")
        return 0
    states = check(args.root)
    if len(states) != 1 or next(iter(states)) not in (PRE, POST):
        for s, rows in states.items():
            print(f"sdk-install-strings: {', '.join(_where(i) for i in rows)}: {s}", file=sys.stderr)
        return 1
    print(f"sdk-install-strings: every install string says {next(iter(states))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
