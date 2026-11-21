#!/usr/bin/env bash
# verify-distribution-readmes.sh — assert npm/observer/README.md and
# pypi/observer/README.md match the result of regenerating them from
# their templates + the shared body (docs/distribution/README-body.md).
#
# Unlike `sync-distribution-readmes`, this NEVER mutates the working
# tree — it builds into temp files and diffs against the committed
# READMEs. That way a local edit that drifts from the templates fails
# loudly instead of being silently overwritten when the gate runs.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

BODY_PATH="docs/distribution/README-body.md"
MARKER='<!-- @@INCLUDE:docs/distribution/README-body.md@@ -->'

if [ ! -f "$BODY_PATH" ]; then
    echo "verify-distribution-readmes: missing $BODY_PATH" >&2
    exit 1
fi

fail=0
# One row per published README: <template name>:<package directory>.
# npm-superbased is the unscoped short-name package (npm/superbased), whose
# README is the npm one with its own title, install lines and short-name note.
for pair in "npm:npm/observer" "pypi:pypi/observer" "npm-superbased:npm/superbased"; do
    channel="${pair%%:*}"
    pkgdir="${pair#*:}"
    template="docs/distribution/$channel-README.template.md"
    committed="$pkgdir/README.md"
    rebuilt="$tmpdir/$channel-README.md"

    if [ ! -f "$template" ]; then
        echo "verify-distribution-readmes: missing $template" >&2
        exit 1
    fi
    if [ ! -f "$committed" ]; then
        echo "verify-distribution-readmes: missing $committed" >&2
        exit 1
    fi

    count=$(grep -cF "$MARKER" "$template" || true)
    if [ "$count" != "1" ]; then
        echo "verify-distribution-readmes: $template has $count include markers, want exactly 1" >&2
        exit 1
    fi

    python3 - "$template" "$rebuilt" "$MARKER" "$BODY_PATH" <<'PY'
import pathlib, sys
template, output, marker, body_path = sys.argv[1:5]
body = pathlib.Path(body_path).read_text()
content = pathlib.Path(template).read_text()
content = content.replace(marker, body.rstrip("\n"))
pathlib.Path(output).write_text(content)
PY

    if ! diff -u "$committed" "$rebuilt" > "$tmpdir/$channel.diff"; then
        echo "verify-distribution-readmes: $committed drifted from $template + $BODY_PATH"
        echo "----- diff: committed (a) vs rebuilt (b) -----"
        cat "$tmpdir/$channel.diff"
        echo "-----"
        fail=1
    fi
done

if [ "$fail" != "0" ]; then
    echo "distribution README drift detected; run 'make sync-distribution-readmes' and commit" >&2
    exit 1
fi

echo "distribution READMEs: in sync with templates + $BODY_PATH"
