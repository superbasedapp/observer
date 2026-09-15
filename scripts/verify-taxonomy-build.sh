#!/usr/bin/env bash
# verify-taxonomy-build.sh — assert the committed shared/lib/actiontax.gen.*
# artifacts match a fresh run of web/taxgen.
#
# web/taxgen is the SOLE writer of those files: it mirrors internal/tooltax
# (the one Go owner of the cross-adapter tool/MCP taxonomy) into the shape
# the dashboard reads — the category list, the action-type →
# {category, label} registry, the MCP parse rules
# (docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §1), the
# ActionCategory literal union (actiontax.gen.ts, which is what makes a
# missing colour a tsc error) and the parity vectors the TypeScript gate
# runs (actiontax.vectors.gen.json — see verify-taxonomy-ts.sh).
#
# Like website/track-gen and plugins/plugingen, it is invoked by hand
# (`make taxonomy-build`), so a taxonomy change can ship with the
# dashboard still rendering last month's categories — exactly the drift
# that made the frontend grow its own taxonomy in the first place. This
# gate closes that gap.
#
# Like verify-plugins-build.sh, this NEVER mutates the working tree and
# NEVER shells out to git: it regenerates into a scratch directory and
# byte-diffs against the committed files.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

COMMITTED_DIR="shared/lib"
# Every artifact taxgen writes. A file added here without being added to
# taxgen (or vice versa) fails loudly below rather than going unchecked.
ARTIFACTS=(actiontax.gen.json actiontax.gen.ts actiontax.vectors.gen.json)

if [ ! -d "web/taxgen" ]; then
    echo "verify-taxonomy-build: missing web/taxgen" >&2
    exit 1
fi
for name in "${ARTIFACTS[@]}"; do
    if [ ! -f "$COMMITTED_DIR/$name" ]; then
        echo "verify-taxonomy-build: missing $COMMITTED_DIR/$name — run 'make taxonomy-build' and commit" >&2
        exit 1
    fi
done

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

go run ./web/taxgen -outdir "$tmpdir" \
    || { echo "verify-taxonomy-build: taxgen failed" >&2; exit 1; }

drift=0
for name in "${ARTIFACTS[@]}"; do
    if [ ! -f "$tmpdir/$name" ]; then
        echo "verify-taxonomy-build: taxgen did not emit $name" >&2
        exit 1
    fi
    if ! diff -u "$COMMITTED_DIR/$name" "$tmpdir/$name" > "$tmpdir/.diff-$name" 2>&1; then
        echo "verify-taxonomy-build: $COMMITTED_DIR/$name drifted from a fresh taxgen run"
        echo "----- diff: committed (-) vs rebuilt (+) -----"
        cat "$tmpdir/.diff-$name"
        echo "-----"
        drift=1
    fi
done

if [ "$drift" -ne 0 ]; then
    echo "taxonomy drift detected; run 'make taxonomy-build' and commit" >&2
    exit 1
fi

echo "action taxonomy: ${#ARTIFACTS[@]} generated files in $COMMITTED_DIR in sync with internal/tooltax"
