#!/usr/bin/env bash
# verify-taxonomy-migration.sh — assert the committed backfill migration
# internal/db/migrations/223_tooltax_action_type_backfill_3.sql matches a
# fresh run of internal/db/taxbackfillgen.
#
# taxbackfillgen is the SOLE writer of that file. It transposes
# internal/tooltax — the one Go owner of the cross-adapter tool/MCP
# taxonomy — into the historical-data repair the plan requires
# (docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §3:
# "sourced FROM the tooltax table at generation time, never
# hand-edited"). A hand-edit, or a tooltax row that moved without a
# matching `make taxonomy-migration-build`, is drift between the SQL and
# the taxonomy it claims to apply.
#
# Note the migration is APPLY-ONCE by nature: regenerating it after it
# has shipped changes bytes a user's database has already consumed
# (migrations are keyed by version, not by content). 077 shipped in v1.36.0
# and 196 in v1.37.0; both are FROZEN as shipped (released-step rule, D-880,
# T-982, docs/migration-numbering.md). 223 re-applies the full current table
# and is safe on a database that ran 077 and 196 (every statement only moves
# rows out of 'unknown'). Until the release that carries 223 is out, keep 223
# in sync; after that, a tooltax change needs yet another NEW step (point
# taxbackfillgen's migrationName at it), never a regenerated 223. This gate
# and TestShippedMigrationsNeverChange both fail on a regenerated shipped
# step.
#
# Like verify-taxonomy-build.sh, this NEVER mutates the working tree and
# NEVER shells out to git: it regenerates into a scratch directory and
# byte-diffs against the committed file.

set -euo pipefail

# The gate itself is scripts/verify-generated.sh, the one implementation
# of the regenerate-and-diff drift gate; this wrapper names the generator
# and the committed files it owns.
exec "$(dirname "$0")/verify-generated.sh" \
    --name verify-taxonomy-migration \
    --tool taxbackfillgen \
    --tool-dir internal/db/taxbackfillgen \
    --make taxonomy-migration-build \
    --drift "taxonomy migration" \
    --ok "taxonomy backfill migration: internal/db/migrations/223_tooltax_action_type_backfill_3.sql in sync with internal/tooltax" \
    --artifact internal/db/migrations/223_tooltax_action_type_backfill_3.sql \
    -- go run ./internal/db/taxbackfillgen -outdir @TMP@
