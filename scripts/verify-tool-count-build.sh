#!/usr/bin/env bash
# verify-tool-count-build.sh — assert the committed
# website/tools/tool-count-manifest.json matches a fresh run of
# tools/toolcountgen.
#
# tools/toolcountgen is the SOLE writer of that file: it partitions
# internal/integration.Tools() (the one-owner adapter capability registry)
# into editorial families via an explicit, documented fold table, and sums
# their weights into the adapterCount that website/tools/accuracy-check.mjs
# cross-checks against CLAUDE.md's own "Platform adapters (N)" prose line.
#
# Like web/taxgen and website/track-gen, it is invoked by hand (`make
# tool-count-build`), so a registry change can ship with the manifest still
# reporting last month's count — exactly the drift class this gate exists
# to close.
#
# Like verify-taxonomy-build.sh, this NEVER mutates the working tree and
# NEVER shells out to git: it regenerates into a scratch directory and
# byte-diffs against the committed file.

set -euo pipefail

# The gate itself is scripts/verify-generated.sh, the one implementation
# of the regenerate-and-diff drift gate; this wrapper names the generator
# and the committed files it owns.
exec "$(dirname "$0")/verify-generated.sh" \
    --name verify-tool-count-build \
    --tool toolcountgen \
    --tool-dir tools/toolcountgen \
    --make tool-count-build \
    --drift tool-count \
    --ok "tool-count manifest: website/tools/tool-count-manifest.json in sync with internal/integration" \
    --artifact website/tools/tool-count-manifest.json \
    -- go run ./tools/toolcountgen -outdir @TMP@
