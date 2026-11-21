#!/usr/bin/env bash
# verify-docs-build.sh: assert the committed /docs render (website/docs/**,
# plus website/assets/css/docs-chroma.css) and the changelog-derived docs
# sources match a fresh `make docs-build`.
#
# Usage:
#   scripts/verify-docs-build.sh              the gate
#   scripts/verify-docs-build.sh --self-test  prove the gate catches drift
#
# Like verify-website-build.sh, this NEVER mutates the working tree. It copies
# website/docs-src, sitemap-pages.xml and feed.xml into a temp dir, runs
# changeloggen against the copies, renders gen into the temp dir (the two
# generators `make docs-build` runs, in its order), and diffs. A hand edit to a rendered page, a docs-src edit committed
# without a re-render, a CHANGELOG.md edit without a re-render, and an orphan
# page (a committed render whose source left nav.toml; gen never deletes) all
# fail here.
#
# Dates are masked before the diff. gen stamps each page's
# article:modified_time and JSON-LD dateModified with `git log -1 --format=%cs`
# of its SOURCE file. A render committed together with its source edit carries
# the source's PREVIOUS commit date, and a rebase rewrites committer dates, so
# an exact date compare fails on correct renders. The masked fields are only
# those two; every other byte is compared.
#
# Origin: F-15 in docs/audits/plane-a-b-definition-sweep-2026-11-20.md (the
# render was 138 files stale with no gate). Mirrors verify-website-build.sh.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

SRC_DIR="website/docs-src"
DOCS_DIR="website/docs"
CHROMA="website/assets/css/docs-chroma.css"
SITEMAP="website/sitemap-pages.xml"
FEED="website/feed.xml"

for p in "$SRC_DIR" "$DOCS_DIR" "$CHROMA" "$SITEMAP" "$FEED" CHANGELOG.md; do
    if [ ! -e "$p" ]; then
        echo "verify-docs-build: missing $p" >&2
        exit 1
    fi
done

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# render: run both generators into $tmpdir; nothing in the tree is written.
render() {
    cp -r "$SRC_DIR" "$tmpdir/docs-src"
    cp "$SITEMAP" "$tmpdir/sitemap-pages.xml"
    cp "$FEED" "$tmpdir/feed.xml"
    mkdir -p "$tmpdir/docs" "$tmpdir/assets/css"
    # The generators resolve paths relative to website/docs-tools, the way
    # `make docs-build` invokes them; the temp paths are absolute.
    (cd website/docs-tools && go run ./changeloggen \
        -changelog ../../CHANGELOG.md \
        -src "$tmpdir/docs-src" \
        -sitemap "$tmpdir/sitemap-pages.xml" \
        -feed "$tmpdir/feed.xml") >/dev/null 2>"$tmpdir/.changeloggen.log" \
        || { cat "$tmpdir/.changeloggen.log" >&2; echo "verify-docs-build: changeloggen failed" >&2; exit 1; }
    # gen reads the REAL docs-src, not the copy: nav.toml [roots] name
    # directories relative to docs-src (sdk = "../../docs/sdk"), which a copy
    # would break. That is exact whenever the copy above matched the real
    # tree, and when it did not, compare's step 1 already fails the gate.
    (cd website/docs-tools && go run ./gen \
        -src "../docs-src" \
        -out "$tmpdir/docs" \
        -assets "$tmpdir/assets") >/dev/null 2>"$tmpdir/.gen.log" \
        || { cat "$tmpdir/.gen.log" >&2; echo "verify-docs-build: gen failed" >&2; exit 1; }
}

# mask_dates FILE OUT: copy FILE to OUT with the two git-derived dates blanked.
mask_dates() {
    sed -E \
        -e 's|(<meta property="article:modified_time" content=")[0-9]{4}-[0-9]{2}-[0-9]{2}(">)|\1DATE\2|g' \
        -e 's|("dateModified":")[0-9]{4}-[0-9]{2}-[0-9]{2}(")|\1DATE\2|g' \
        "$1" > "$2"
}

# compare DOCS CHROMA SRC SITEMAP FEED: compare one committed tree against the
# render in $tmpdir. Prints every drift; returns 1 if any.
compare() {
    local docs="$1" chroma="$2" src="$3" sitemap="$4" feed="$5"
    local fail=0 rendered rel committed f

    # 1. changeloggen output: the derived docs sources must already be current.
    if ! diff -r -q "$src" "$tmpdir/docs-src" > "$tmpdir/.diff-src"; then
        echo "verify-docs-build: $SRC_DIR drifted from a fresh changeloggen run (CHANGELOG.md changed without 'make docs-build'?)"
        cat "$tmpdir/.diff-src"
        fail=1
    fi
    for pair in "$sitemap=$tmpdir/sitemap-pages.xml" "$feed=$tmpdir/feed.xml"; do
        if ! diff -u "${pair%%=*}" "${pair#*=}" > "$tmpdir/.diff"; then
            echo "verify-docs-build: ${pair%%=*} drifted from a fresh changeloggen run"
            cat "$tmpdir/.diff"
            fail=1
        fi
    done

    # 2. Every file gen PRODUCES is committed and matches (dates masked).
    while IFS= read -r rendered; do
        rel="${rendered#"$tmpdir/docs/"}"
        committed="$docs/$rel"
        if [ ! -f "$committed" ]; then
            echo "verify-docs-build: $DOCS_DIR/$rel missing (gen renders it)"
            fail=1
            continue
        fi
        mask_dates "$committed" "$tmpdir/.a"
        mask_dates "$rendered" "$tmpdir/.b"
        if ! diff -u "$tmpdir/.a" "$tmpdir/.b" > "$tmpdir/.diff"; then
            echo "verify-docs-build: $DOCS_DIR/$rel drifted from $SRC_DIR"
            echo "----- diff: committed (a) vs rebuilt (b) -----"
            head -n 60 "$tmpdir/.diff"
            echo "-----"
            fail=1
        fi
    done < <(find "$tmpdir/docs" -type f | sort)

    if ! diff -u "$chroma" "$tmpdir/assets/css/docs-chroma.css" > "$tmpdir/.diff"; then
        echo "verify-docs-build: $CHROMA drifted from a fresh gen run"
        cat "$tmpdir/.diff"
        fail=1
    fi

    # 3. Orphans: every committed file under website/docs is one gen still
    # produces. gen writes but never deletes, so a page dropped from nav.toml
    # leaves its old render behind until someone removes it.
    while IFS= read -r f; do
        rel="${f#"$docs/"}"
        if [ ! -f "$tmpdir/docs/$rel" ]; then
            echo "verify-docs-build: $DOCS_DIR/$rel is not produced by gen (orphan: its source left nav.toml); delete it or restore the source"
            fail=1
        fi
    done < <(find "$docs" -type f | sort)

    return "$fail"
}

# self_test: copy the committed tree, apply one mutation per case, and require
# compare to fail on each drift and pass on a date-only change.
self_test() {
    local work="$tmpdir/selftest" bad=0 page
    page="sdk/overview.html"
    reset() {
        rm -rf "$work"
        mkdir -p "$work"
        cp -r "$DOCS_DIR" "$work/docs"
        cp "$CHROMA" "$work/chroma.css"
        cp -r "$SRC_DIR" "$work/docs-src"
        cp "$SITEMAP" "$work/sitemap.xml"
        cp "$FEED" "$work/feed.xml"
    }
    run_case() { # name want(pass|fail)
        local got=pass
        compare "$work/docs" "$work/chroma.css" "$work/docs-src" "$work/sitemap.xml" "$work/feed.xml" >/dev/null || got=fail
        if [ "$got" = "$2" ]; then
            echo "self-test ok:   $1 ($got)"
        else
            echo "self-test FAIL: $1 (want $2, got $got)"
            bad=1
        fi
    }

    reset; run_case "committed tree as is" pass
    reset; sed -i 's|</main>|<p>hand edit</p></main>|' "$work/docs/$page"; run_case "hand edit to a rendered page" fail
    reset; rm "$work/docs/$page"; run_case "rendered page deleted" fail
    reset; echo '<p>orphan</p>' > "$work/docs/sdk/orphan.html"; run_case "orphan render" fail
    reset; echo '/* edit */' >> "$work/chroma.css"; run_case "hand edit to docs-chroma.css" fail
    reset; printf '\nhand edit\n' >> "$work/docs-src/changelog.md"; run_case "changelog.md out of step with CHANGELOG.md" fail
    reset; sed -i -E 's|"dateModified":"[0-9-]{10}"|"dateModified":"1999-01-01"|; s|(article:modified_time" content=")[0-9-]{10}|\11999-01-01|' "$work/docs/$page"; run_case "date-only change (masked)" pass

    return "$bad"
}

render

case "${1:-}" in
    --self-test)
        if ! grep -q '</main>' "$DOCS_DIR/sdk/overview.html"; then
            echo "verify-docs-build: self-test fixture page lacks </main>" >&2
            exit 1
        fi
        if self_test; then
            echo "verify-docs-build self-test: every case behaved"
            exit 0
        fi
        echo "verify-docs-build self-test: the gate missed a case" >&2
        exit 1
        ;;
    "")
        ;;
    *)
        echo "usage: $0 [--self-test]" >&2
        exit 2
        ;;
esac

if ! compare "$DOCS_DIR" "$CHROMA" "$SRC_DIR" "$SITEMAP" "$FEED"; then
    echo "docs drift detected; edit website/docs-src/ (or CHANGELOG.md), run 'make docs-build', and commit" >&2
    exit 1
fi

echo "docs: website/docs in sync with $SRC_DIR"
