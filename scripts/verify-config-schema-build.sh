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

# The gate itself is scripts/verify-generated.sh, the one implementation
# of the regenerate-and-diff drift gate; this wrapper names the generator
# and the committed files it owns.
exec "$(dirname "$0")/verify-generated.sh" \
    --name verify-config-schema-build \
    --tool cfgschema \
    --tool-dir web/cfgschema \
    --make config-schema-build \
    --drift "config schema" \
    --ok "config schema: internal/config/schema/schema.gen.json + web/src/lib/configschema.gen.ts in sync with internal/configschema" \
    --quiet \
    --artifact internal/config/schema/schema.gen.json \
    --artifact web/src/lib/configschema.gen.ts \
    -- go run ./web/cfgschema -root @ROOT@ -json @TMP@/schema.gen.json -types @TMP@/configschema.gen.ts
