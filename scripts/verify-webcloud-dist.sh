#!/usr/bin/env bash
# verify-webcloud-dist.sh — assert the committed webcloud/dist (the SPA
# cmd/observer-cloud go:embed's — webcloud/embed.go: `//go:embed all:dist`)
# matches a fresh `vite build` of webcloud/src.
#
# Two consecutive `vite build` runs of this project were verified
# byte-for-byte identical (2026-09-11: hashed asset filenames, JS and CSS
# bundle contents all matched exactly across two runs from a clean state) —
# so unlike scripts/verify-config-schema-build.sh (which diffs generated
# text against committed text), this can do a straightforward `diff -r`
# against a fresh build rather than a file-set/size comparison. If a future
# dependency bump or plugin introduces nondeterminism (content-hash orders,
# a machine-local absolute path baked into a source map, etc.), this script's
# `diff -r` will start failing on every unrelated PR — the fix at that point
# is documented inline below, not a silent switch to a weaker check.
#
# Like verify-config-schema-build.sh and verify-taxonomy-build.sh, this NEVER
# mutates the working tree and NEVER shells out to git: it builds into a
# scratch directory and diffs against the committed webcloud/dist.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

WEBCLOUD_DIR="webcloud"
COMMITTED_DIST="$WEBCLOUD_DIR/dist"

if [ ! -d "$WEBCLOUD_DIR" ]; then
    echo "verify-webcloud-dist: missing $WEBCLOUD_DIR" >&2
    exit 1
fi
if [ ! -d "$COMMITTED_DIST" ]; then
    echo "verify-webcloud-dist: missing $COMMITTED_DIST — run 'cd webcloud && npx vite build' and commit" >&2
    exit 1
fi
if [ ! -d "$WEBCLOUD_DIR/node_modules" ]; then
    echo "verify-webcloud-dist: missing $WEBCLOUD_DIR/node_modules — run 'npm ci' first (this is an npm workspace: 'npm ci' from the repo root, or from $WEBCLOUD_DIR/, both resolve against the root lockfile)" >&2
    exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

(
    cd "$WEBCLOUD_DIR"
    npx vite build --outDir "$tmpdir/dist" --emptyOutDir >"$tmpdir/build.log" 2>&1
) || {
    echo "verify-webcloud-dist: vite build failed" >&2
    cat "$tmpdir/build.log" >&2
    exit 1
}

if ! diff -rq "$COMMITTED_DIST" "$tmpdir/dist" >"$tmpdir/diff.log" 2>&1; then
    echo "verify-webcloud-dist: $COMMITTED_DIST drifted from a fresh vite build" >&2
    echo "----- diff -rq: committed vs fresh build -----" >&2
    cat "$tmpdir/diff.log" >&2
    echo "-----" >&2
    echo "verify-webcloud-dist: run 'cd webcloud && npx vite build' and commit the result." >&2
    echo "If this failure is NOT from an actual src/ change (e.g. hashed filenames differ" >&2
    echo "between two otherwise-identical builds), vite build has stopped being" >&2
    echo "deterministic on this toolchain version — replace this diff -r with a" >&2
    echo "file-set + size comparison (see this script's header) rather than disabling the gate." >&2
    exit 1
fi

echo "webcloud dist: $COMMITTED_DIST matches a fresh vite build"
