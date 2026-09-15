#!/usr/bin/env bash
# verify-taxonomy-ts.sh — compile the REAL shared/lib/actions.ts and run
# it against the vectors web/taxgen generated from internal/tooltax.
#
# Why a second gate: verify-taxonomy-build.sh proves the GENERATED files
# match tooltax. It says nothing about whether the TypeScript that reads
# them still behaves like Go — and the first cut of WP-T2 pinned that
# with a Go reference implementation inside web/taxgen/main_test.go,
# which can only prove Go agrees with Go (reverting actions.ts's
# separatorMinIndex guard left it green). This gate executes the real
# thing: esbuild bundles actions.ts, node runs mcpIdentity/actionMeta
# over shared/lib/actiontax.vectors.gen.json, whose expectations are
# derived from tooltax.MCPIdentity at generation time.
#
# Like the other verify-* gates this NEVER mutates the working tree and
# NEVER shells out to git: it bundles into a temp dir.
#
# Requires web/node_modules (esbuild) — `cd web && npm ci`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SOURCE="shared/lib/actions.ts"
VECTORS="shared/lib/actiontax.vectors.gen.json"
TAXONOMY="shared/lib/actiontax.gen.json"
ESBUILD="web/node_modules/.bin/esbuild"
GATE="scripts/taxonomy-ts-gate.mjs"

for f in "$SOURCE" "$VECTORS" "$TAXONOMY" "$GATE"; do
    if [ ! -f "$f" ]; then
        echo "verify-taxonomy-ts: missing $f — run 'make taxonomy-build'" >&2
        exit 1
    fi
done

if [ ! -x "$ESBUILD" ]; then
    echo "verify-taxonomy-ts: missing $ESBUILD — run 'cd web && npm ci'" >&2
    exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# --bundle inlines the imported actiontax.gen.json (esbuild's default
# json loader), so the module under test carries the same generated data
# the browser bundle does. The type-only import of actiontax.gen.ts is
# erased, as it is in the vite build.
"$ESBUILD" "$SOURCE" \
    --bundle \
    --format=esm \
    --platform=node \
    --log-level=warning \
    --outfile="$tmpdir/actions.mjs" \
    || { echo "verify-taxonomy-ts: esbuild failed on $SOURCE" >&2; exit 1; }

node "$GATE" "$tmpdir/actions.mjs" "$VECTORS" "$TAXONOMY"
