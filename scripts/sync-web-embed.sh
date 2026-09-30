#!/usr/bin/env bash
# sync-web-embed.sh SRC_DIST EMBED_DIR — refresh a go:embed'd dashboard
# bundle from a fresh Vite build.
#
# The ONE owner of "Vite output -> committed embed dir". Every path that
# fills an embed dir calls this script, so the local rebuild, the CI drift
# gates and the release pipeline can never disagree about what the embed
# holds:
#
#   make web-build         web/dist  -> internal/intelligence/dashboard/webapp/dist
#   make web-build-org     web2/dist -> internal/orgserver/dashboard/webapp/dist
#   ci.yml / ci-private.yml dist-consistency gates (same pairs, then diff)
#   npm-release.yml        build job "Sync embed dir from web/dist"
#   scripts/release.sh     preflight_checks embed gate
#
# Source maps (*.map) are NOT copied. They were ~10 MB per dashboard - about
# three quarters of each committed embed tree and of each binary's embedded
# UI - and every rebuild re-committed them under new content-hashed names.
# The org server already refused to serve them publicly
# (webapp.IsPublicAsset). The maps stay in web/dist / web2/dist (ignored
# build outputs) for local debugging with `vite preview` / `npm run dev`.
#
# Deliberately a plain copy: no hashing, no rewriting of the bundles, so a
# fresh build synced here is byte-identical to the committed embed whenever
# the sources are unchanged (the drift gates rely on that).
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SRC_DIST EMBED_DIR" >&2
    exit 2
fi
src=$1
dst=$2

if [ ! -f "$src/index.html" ]; then
    echo "sync-web-embed: $src/index.html missing - run the Vite build first" >&2
    exit 1
fi

rm -rf "$dst"
mkdir -p "$dst"
cp -R "$src/." "$dst/"
find "$dst" -type f -name '*.map' -delete

files=$(find "$dst" -type f | wc -l | tr -d ' ')
echo "sync-web-embed: $src -> $dst ($files files, source maps excluded)"
