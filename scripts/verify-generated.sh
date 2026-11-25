#!/usr/bin/env bash
# verify-generated.sh — the one implementation of the "regenerate into a
# scratch directory and byte-diff against the committed files" drift gate.
#
# The single-generator verify-*.sh scripts (verify-taxonomy-migration,
# verify-reasoning-migration, verify-assistant-migration,
# verify-tool-count-build, verify-taxonomy-build,
# verify-config-schema-build) are thin wrappers that exec this script with
# their own name, generator and files, so the Makefile targets, workflows
# and docs keep calling them by name. Like every verify-* gate this NEVER
# mutates the working tree and NEVER shells out to git.
#
# Usage:
#   verify-generated.sh --name NAME --tool TOOL --tool-dir DIR \
#       --make TARGET --drift LABEL --ok MESSAGE [--quiet] \
#       --artifact COMMITTED [--artifact COMMITTED ...] \
#       -- GENERATOR ARGV...
#
#   --name      the gate's name, the prefix of every error line
#               (e.g. verify-taxonomy-migration)
#   --tool      the generator's short name, used in "<tool> failed" and
#               "a fresh <tool> run"
#   --tool-dir  the generator's source directory; the gate fails if it is
#               missing
#   --make      the make target that regenerates the files
#   --drift     the label of the final "<label> drift detected" line
#   --ok        the line printed when every file is in sync; @COUNT@ in it
#               is replaced by the number of --artifact files
#   --quiet     discard the generator's standard output
#   --artifact  a committed file (relative to the repository root); the
#               generator must write a file of the same base name into the
#               scratch directory. Repeat for each file, in report order.
#
# In the generator argv, @TMP@ is replaced by the scratch directory and
# @ROOT@ by the repository root.
#
# Exit status: 0 when every file is in sync; 1 on drift or on any other
# failure (missing generator or file, generator error, file not emitted);
# 2 on a usage error.

set -euo pipefail

usage() {
    echo "usage: $0 --name NAME --tool TOOL --tool-dir DIR --make TARGET --drift LABEL --ok MESSAGE [--quiet] --artifact FILE... -- GENERATOR ARGV..." >&2
    exit 2
}

name="" tool="" tool_dir="" target="" drift_label="" ok="" quiet=0
artifacts=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --name) name="$2"; shift 2 ;;
        --tool) tool="$2"; shift 2 ;;
        --tool-dir) tool_dir="$2"; shift 2 ;;
        --make) target="$2"; shift 2 ;;
        --drift) drift_label="$2"; shift 2 ;;
        --ok) ok="$2"; shift 2 ;;
        --quiet) quiet=1; shift ;;
        --artifact) artifacts+=("$2"); shift 2 ;;
        --) shift; break ;;
        *) usage ;;
    esac
done
if [ -z "$name" ] || [ -z "$tool" ] || [ -z "$tool_dir" ] || [ -z "$target" ] \
    || [ -z "$drift_label" ] || [ -z "$ok" ] || [ "${#artifacts[@]}" -eq 0 ] || [ "$#" -eq 0 ]; then
    usage
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -d "$tool_dir" ]; then
    echo "$name: missing $tool_dir" >&2
    exit 1
fi
for f in "${artifacts[@]}"; do
    if [ ! -f "$f" ]; then
        echo "$name: missing $f — run 'make $target' and commit" >&2
        exit 1
    fi
done

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

argv=()
for a in "$@"; do
    a="${a//@TMP@/$tmpdir}"
    a="${a//@ROOT@/$REPO_ROOT}"
    argv+=("$a")
done

if [ "$quiet" -eq 1 ]; then
    "${argv[@]}" >/dev/null || { echo "$name: $tool failed" >&2; exit 1; }
else
    "${argv[@]}" || { echo "$name: $tool failed" >&2; exit 1; }
fi

drift=0
for committed in "${artifacts[@]}"; do
    base=$(basename "$committed")
    rebuilt="$tmpdir/$base"
    if [ ! -f "$rebuilt" ]; then
        echo "$name: $tool did not emit $base" >&2
        exit 1
    fi
    if ! diff -u "$committed" "$rebuilt" > "$tmpdir/.diff-$base" 2>&1; then
        echo "$name: $committed drifted from a fresh $tool run"
        echo "----- diff: committed (-) vs rebuilt (+) -----"
        cat "$tmpdir/.diff-$base"
        echo "-----"
        drift=1
    fi
done

if [ "$drift" -ne 0 ]; then
    echo "$drift_label drift detected; run 'make $target' and commit" >&2
    exit 1
fi

echo "${ok//@COUNT@/${#artifacts[@]}}"
