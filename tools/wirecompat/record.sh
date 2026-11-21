#!/usr/bin/env bash
# tools/wirecompat/record.sh: record golden org push envelopes for one node
# version into testdata/wirecompat/<version>/ (managed-SaaS plan 07 M1.5,
# plan 06 section 18.2.7, decision D-30).
#
#   tools/wirecompat/record.sh <ref> <version> [<out-dir>]
#
#   <ref>      the commit to record: a release tag (v1.31.0), HEAD, main ...
#   <version>  the directory name and version label: v<major>.<minor>.<patch>
#              or "main" (an unreleased tree)
#   <out-dir>  default: <repo>/testdata/wirecompat/<version>
#
# How: the commit is checked out into a temporary `git worktree` (removed
# on exit), this directory's non-test Go files are copied into it over
# whatever tools/wirecompat the commit has, and the recorder is built THERE,
# so it drives that version's own store, orgclient and push path. It then
# runs with HOME and every per-user directory pointed into a throwaway
# directory, with OBSERVER_* / SBO_* variables unset, and with the host's
# name, user, home and repository path as -forbid values (the recorder
# refuses to write an envelope containing any of them).
#
# The release date written to meta.json: the tag's date when <version> is
# an existing tag, the commit's date for "main", otherwise today (the
# release being cut, scripts/release.sh preflight). All dates are UTC.
#
# Exit: 0 when the directory was written, non-zero (and nothing written)
# otherwise.
set -euo pipefail

die() { echo "wirecompat/record.sh: $*" >&2; exit 1; }

[ $# -ge 2 ] && [ $# -le 3 ] || die "usage: record.sh <ref> <version> [<out-dir>]"
ref=$1
version=$2

case "$version" in
    main) ;;
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) die "version '$version' must be main or v<major>.<minor>.<patch>" ;;
esac

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
out=${3:-$repo/testdata/wirecompat/$version}
case "$out" in
    /*|[A-Za-z]:*) ;;
    *) out="$PWD/$out" ;;
esac

commit=$(git -C "$repo" rev-parse --verify --quiet "$ref^{commit}") \
    || die "'$ref' is not a commit in $repo"

if [ "$version" = main ]; then
    released=$(TZ=UTC0 git -C "$repo" log -1 --date=format-local:%Y-%m-%d --format=%cd "$commit")
    agent_version=dev
elif git -C "$repo" rev-parse --verify --quiet "refs/tags/$version" >/dev/null; then
    released=$(TZ=UTC0 git -C "$repo" for-each-ref --format='%(creatordate:format-local:%Y-%m-%d)' "refs/tags/$version")
    agent_version=${version#v}
else
    released=$(date -u +%Y-%m-%d)
    agent_version=${version#v}
fi
[ -n "$released" ] || die "could not date $version"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/wirecompat-XXXXXX")
wt="$scratch/tree"
cleanup() {
    if [ -d "$wt" ]; then
        git -C "$repo" worktree remove --force "$wt" >/dev/null 2>&1 || true
    fi
    git -C "$repo" worktree prune >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT

echo ">> wirecompat: $version from ${commit:0:10} (released $released, agent_version $agent_version)"
git -C "$repo" worktree add --detach --quiet "$wt" "$commit" \
    || die "git worktree add failed"

# The recorder: this directory's non-test Go files, over the commit's own.
mkdir -p "$wt/tools/wirecompat"
rm -f "$wt"/tools/wirecompat/*.go
for f in "$here"/*.go; do
    case "$f" in *_test.go) continue ;; esac
    cp "$f" "$wt/tools/wirecompat/"
done

exe=""
case "$(go env GOOS)" in windows) exe=.exe ;; esac
bin="$scratch/wirecompat$exe"
(cd "$wt" && GOWORK=off go build -trimpath -o "$bin" ./tools/wirecompat) \
    || die "the recorder did not build against $version (an API it uses changed at that commit; see tools/wirecompat/doc.go)"

# Isolated per-user directories, and the host's identity as forbidden text.
fake="$scratch/home"
mkdir -p "$fake/appdata" "$fake/localappdata" "$fake/config" "$fake/data" "$fake/cache" "$fake/state"
forbid=()
add_forbid() { [ -n "${1:-}" ] && forbid+=(-forbid "$1"); return 0; }
add_forbid "$(hostname 2>/dev/null || true)"
add_forbid "${USER:-}"
add_forbid "${USERNAME:-}"
add_forbid "${HOME:-}"
add_forbid "${USERPROFILE:-}"
add_forbid "$repo"
if command -v cygpath >/dev/null 2>&1; then
    add_forbid "$(cygpath -w "$HOME" 2>/dev/null || true)"
    add_forbid "$(cygpath -w "$repo" 2>/dev/null || true)"
fi
unset_args=()
while IFS='=' read -r name _; do
    case "$name" in OBSERVER_*|SBO_*) unset_args+=(-u "$name") ;; esac
done < <(env)

(cd "$scratch" && env "${unset_args[@]}" \
    HOME="$fake" USERPROFILE="$fake" APPDATA="$fake/appdata" LOCALAPPDATA="$fake/localappdata" \
    XDG_CONFIG_HOME="$fake/config" XDG_DATA_HOME="$fake/data" XDG_CACHE_HOME="$fake/cache" XDG_STATE_HOME="$fake/state" \
    "$bin" -out "$out" -version "$version" -agent-version "$agent_version" \
        -released "$released" -commit "$commit" "${forbid[@]}") \
    || die "recording $version failed (above)"

echo "   wrote $out"
