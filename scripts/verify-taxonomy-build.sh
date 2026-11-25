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

# The gate itself is scripts/verify-generated.sh, the one implementation
# of the regenerate-and-diff drift gate; this wrapper names the generator
# and the committed files it owns.
#
# Every artifact taxgen writes. A file added here without being added to
# taxgen (or vice versa) fails loudly below rather than going unchecked.
exec "$(dirname "$0")/verify-generated.sh" \
    --name verify-taxonomy-build \
    --tool taxgen \
    --tool-dir web/taxgen \
    --make taxonomy-build \
    --drift taxonomy \
    --ok "action taxonomy: @COUNT@ generated files in shared/lib in sync with internal/tooltax" \
    --artifact shared/lib/actiontax.gen.json \
    --artifact shared/lib/actiontax.gen.ts \
    --artifact shared/lib/actiontax.vectors.gen.json \
    -- go run ./web/taxgen -outdir @TMP@
