#!/usr/bin/env bash
# website-stage-connect.sh: copy the one-command connect wrappers
# (scripts/connect.sh, scripts/connect.ps1) into the site root so
# https://superbased.app/connect.sh and /connect.ps1 serve them.
#
# Getting started v2 (2026-11-17), shared contract C: the wrappers download
# the signed installer and run it with --connect. They are copied at website
# build time and never committed under website/ (.gitignore), so there is
# exactly one source: scripts/. The worker (website/_worker.js, the
# connect-script route) serves them as text/plain with a short cache.
#
#   scripts/website-stage-connect.sh            copy what exists, warn on a gap
#   scripts/website-stage-connect.sh --require  fail when a wrapper is missing
#
# `make website-build` runs the first form (local preview); the Website
# Deploy workflow runs --require, so production never ships a /connect.sh
# that 404s.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

require=0
if [ "${1:-}" = "--require" ]; then
    require=1
fi

missing=0
for f in connect.sh connect.ps1; do
    src="scripts/$f"
    dst="website/$f"
    if [ ! -f "$src" ]; then
        echo "website-stage-connect: $src not found; /$f is not served until it exists" >&2
        rm -f "$dst"
        missing=1
        continue
    fi
    # These are served as text/plain and piped into a shell: refuse anything
    # that is not a plain script (an HTML error page saved by mistake, say).
    if head -c 512 "$src" | grep -qiE '<!doctype|<html'; then
        echo "website-stage-connect: $src looks like HTML, refusing to stage it" >&2
        exit 1
    fi
    cp "$src" "$dst"
    echo "website-stage-connect: staged $dst"
done

if [ "$missing" = 1 ] && [ "$require" = 1 ]; then
    echo "website-stage-connect: --require and a wrapper is missing" >&2
    exit 1
fi
