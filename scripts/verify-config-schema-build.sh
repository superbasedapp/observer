#!/usr/bin/env bash
# verify-config-schema-build.sh — assert the committed config-schema
# artifacts match a fresh run of web/cfgschema.
#
# web/cfgschema is the SOLE writer of:
#   internal/config/schema/schema.gen.json   (go:embed'd; GET /api/config/schema)
#   web/src/lib/configschema.gen.ts          (the ConfigKeyPath literal union)
#
# It serializes internal/configschema — the one Go owner of config.Config's
# structure + classification (tier / restart class / section / prominence)
# — plus every field's Go doc comment. Like web/taxgen it is invoked by
# hand (`make config-schema-build`), so a config change can ship with the
# dashboard still rendering last month's keys; this gate closes that gap
# (docs/plans/dashboard-config-management-plan-2026-08-28.md §1.4 half 1).
#
# Like verify-taxonomy-build.sh, this NEVER mutates the working tree and
# NEVER shells out to git: it regenerates into a scratch directory and
# byte-diffs against the committed files.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

JSON_COMMITTED="internal/config/schema/schema.gen.json"
TYPES_COMMITTED="web/src/lib/configschema.gen.ts"

if [ ! -d "web/cfgschema" ]; then
    echo "verify-config-schema-build: missing web/cfgschema" >&2
    exit 1
fi
for f in "$JSON_COMMITTED" "$TYPES_COMMITTED"; do
    if [ ! -f "$f" ]; then
        echo "verify-config-schema-build: missing $f — run 'make config-schema-build' and commit" >&2
        exit 1
    fi
done

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

go run ./web/cfgschema -root "$REPO_ROOT" -json "$tmpdir/schema.gen.json" -types "$tmpdir/configschema.gen.ts" >/dev/null \
    || { echo "verify-config-schema-build: cfgschema failed" >&2; exit 1; }

drift=0
check() {
    local committed="$1" rebuilt="$2"
    if [ ! -f "$rebuilt" ]; then
        echo "verify-config-schema-build: cfgschema did not emit $(basename "$rebuilt")" >&2
        exit 1
    fi
    if ! diff -u "$committed" "$rebuilt" > "$tmpdir/.diff" 2>&1; then
        echo "verify-config-schema-build: $committed drifted from a fresh cfgschema run"
        echo "----- diff: committed (-) vs rebuilt (+) -----"
        cat "$tmpdir/.diff"
        echo "-----"
        drift=1
    fi
}
check "$JSON_COMMITTED" "$tmpdir/schema.gen.json"
check "$TYPES_COMMITTED" "$tmpdir/configschema.gen.ts"

if [ "$drift" -ne 0 ]; then
    echo "config schema drift detected; run 'make config-schema-build' and commit" >&2
    exit 1
fi

echo "config schema: $JSON_COMMITTED + $TYPES_COMMITTED in sync with internal/configschema"
