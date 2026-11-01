#!/usr/bin/env bash
# omit-tag-check.sh: vet and test every build-tag variant the tree actually
# has, so an off file cannot rot unnoticed (modular packaging plan 5.9 and
# risk R1, "stub rot"; lane MP-REL).
#
#   scripts/omit-tag-check.sh [--vet-only] [--run <regex>] [--list] [--only <set>]
#                              [--scope distro] [--batch <i>/<n>]
#
# The tag set is read from the tree, never from a list in this script: every
# sbo_omit_* tag named in a //go:build line, the one-release alias no_obs,
# and the tag set of every stamped distro (sbo-components distros, then
# sbo-components tags, which add the sbo_distro_* stamps). For each one:
#
#   go vet -tags <tags> ./...                 (every package, tests included:
#                                              vet type-checks every test file)
#   go test -tags <tags> <tagged packages>    (the packages holding a file
#                                              whose build line names a tag
#                                              in the set; --run narrows them)
#
# The four published editions (no_obs and the three distro sets) run the
# full tests of every tagged package. Every other set (a single sbo_omit_*
# tag, custom-build.yml only) runs the full tests of its tagged packages
# except the five heavy ones (heavy_pkgs below); for a heavy package it runs
# only the tests declared in that package's tagged test files, which still
# compiles the whole test binary (-run '^$' when there are none). A set's
# behaviour change is then seen by its own tagged tests, its owner (item 1
# of the test-time plan: the heavy packages took 180 to 230 s per set, 65
# sets, about 230 job-minutes of a full run).
#
# A tag no file names cannot change what compiles, so it is skipped: its
# build is the default build, which the ordinary CI jobs already cover.
# --scope distro keeps only the distro sets and no_obs (the editions
# npm-release publishes); --batch i/n keeps every n-th set from i (0-based).
# Each set prints as a log group; a failing set is named and the run goes on.
# ci.yml runs --scope distro per push and the full list in 6 batches on a
# dispatched full run and a tag push (D-609). On a small host use --vet-only or --run.
set -euo pipefail

vet_only=0 run="" list=0 only="" scope="" batch=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vet-only) vet_only=1; shift ;;
    --run) run="$2"; shift 2 ;;
    --list) list=1; shift ;;
    --only) only="$2"; shift 2 ;;
    # --scope distro: only the distro sets (sbo_distro_* stamp) and no_obs,
    # the editions npm-release publishes. ci.yml runs these on every push.
    --scope) scope="$2"; shift 2 ;;
    # --batch <i>/<n>: every n-th set starting at i (0-based), so CI runs the
    # full list in n jobs that each share one warm build cache (D-609).
    --batch) batch="$2"; shift 2 ;;
    *) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
  esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
export CGO_ENABLED=0

# Tags named in a build line of a tracked Go file.
mapfile -t named < <(git grep -h -E '^//go:build .*(sbo_omit_|no_obs)' -- '*.go' \
  | grep -oE 'sbo_omit_[A-Za-z0-9_]+|no_obs' | sort -u)

sets=()
for t in "${named[@]}"; do sets+=("$t"); done
# The distros come from the catalog too (sbo-components distros: every
# stamped prebuilt distro), so a new distro is checked without an edit here.
mapfile -t distros < <(go run ./cmd/sbo-components distros)
if [[ ${#distros[@]} -eq 0 ]]; then
  echo "omit-tag-check: sbo-components distros listed no distro" >&2
  exit 2
fi
for d in "${distros[@]}"; do
  sets+=("$(go run ./cmd/sbo-components tags --distro "$d")")
done

case "$scope" in
  "") ;;
  distro)
    kept=()
    for s in "${sets[@]}"; do
      if [[ "$s" == "no_obs" || ",$s" == *",sbo_distro_"* ]]; then kept+=("$s"); fi
    done
    sets=("${kept[@]}")
    ;;
  *) echo "omit-tag-check: --scope must be distro" >&2; exit 2 ;;
esac
if [[ -n "$batch" ]]; then
  if [[ ! "$batch" =~ ^([0-9]+)/([0-9]+)$ ]] || (( BASH_REMATCH[2] < 1 || BASH_REMATCH[1] >= BASH_REMATCH[2] )); then
    echo "omit-tag-check: --batch wants <i>/<n> with 0 <= i < n" >&2
    exit 2
  fi
  bi=${BASH_REMATCH[1]} bn=${BASH_REMATCH[2]}
  kept=()
  for k in "${!sets[@]}"; do
    if (( k % bn == bi )); then kept+=("${sets[$k]}"); fi
  done
  sets=("${kept[@]}")
fi

if [[ "$list" -eq 1 ]]; then
  printf '%s\n' "${sets[@]}"
  exit 0
fi
# --only <set>: one entry of --list (the CI matrix runs one set per job).
# A set that is not in the tree's list is refused, so a stale matrix entry
# fails instead of passing vacuously.
if [[ -n "$only" ]]; then
  found=0
  for s in "${sets[@]}"; do [[ "$s" == "$only" ]] && found=1; done
  if [[ "$found" -eq 0 ]]; then
    echo "omit-tag-check: --only $only is not a tag set of this tree (see --list)" >&2
    exit 2
  fi
  sets=("$only")
fi

# nested_modules: the directories of every go.mod below the root. A package
# inside one belongs to that module, which `go test` from the root cannot
# load ([setup failed]), and `go vet ./...` leaves out the same way.
nested_modules() {
  git ls-files -- '*/go.mod' | xargs -r -n1 dirname
}

# tagged_pkgs <comma tags>: the packages of the root module holding a file
# whose build line names one of the tags.
tagged_pkgs() {
  local re mods
  re="$(echo "$1" | tr ',' '|')"
  mods="$(nested_modules)"
  git grep -l -E "^//go:build .*(${re})([^A-Za-z0-9_]|$)" -- '*.go' \
    | xargs -r -n1 dirname | sort -u \
    | while read -r d; do
        inside=0
        while read -r m; do
          [[ -n "$m" && ( "$d" == "$m" || "$d" == "$m"/* ) ]] && { inside=1; break; }
        done <<<"$mods"
        [[ "$inside" -eq 0 ]] && echo "./$d"
      done
}

# heavy_pkgs: the tagged packages whose full test run costs minutes
# (job logs of run 39364803173, -race on every package: cmd/observer 1690 s,
# cmd/observer-org 1087 s, internal/orgserver 965 s, internal/store 510 s,
# internal/intelligence/dashboard 433 s). A non-edition set runs only their
# tagged tests.
heavy_pkgs=(./cmd/observer ./cmd/observer-org ./internal/orgserver ./internal/store ./internal/intelligence/dashboard)

# is_edition <set>: true for the editions npm-release publishes (the same
# rule as --scope distro).
is_edition() {
  [[ "$1" == "no_obs" || ",$1" == *",sbo_distro_"* ]]
}

is_heavy() {
  local h
  for h in "${heavy_pkgs[@]}"; do [[ "$1" == "$h" ]] && return 0; done
  return 1
}

# tagged_tests <comma tags> <./pkg>: the top-level Test functions declared
# in the package's own test files that compile under the set and whose build
# line names one of its tags, as one regex alternation (empty when there are
# none). A file excluded by the set (a !tag line) does not count. Tagged test
# files that declare no Test function make grep exit 1 (xargs 123), which is
# "none", not an error: under set -e it would abort the whole batch.
tagged_tests() {
  local re dir
  re="$(echo "$1" | tr ',' '|')"
  dir="${2#./}"
  comm -12 \
    <(git grep -l -E "^//go:build .*(${re})([^A-Za-z0-9_]|$)" -- "${dir}/*_test.go" \
        | while read -r f; do [[ "$(dirname "$f")" == "$dir" ]] && basename "$f"; done | sort -u) \
    <(go list -tags "$1" -f '{{range .TestGoFiles}}{{println .}}{{end}}{{range .XTestGoFiles}}{{println .}}{{end}}' "$2" | grep . | sort -u) \
    | sed "s#^#${dir}/#" \
    | { xargs -r grep -h -oE '^func Test[A-Za-z0-9_]*\(' || true; } \
    | sed -e 's/^func //' -e 's/($//' | sort -u | paste -sd'|' -
}

fail=0 failed=()
# In GitHub Actions each set is a collapsible log group, so a batch job still
# shows one failure line per set.
gh=0; [[ -n "${GITHUB_ACTIONS:-}" ]] && gh=1
for set in "${sets[@]}"; do
  if [[ "$gh" -eq 1 ]]; then echo "::group::tags: $set"; else echo "== tags: $set"; fi
  ok=1
  if ! go vet -tags "$set" ./...; then
    echo "FAIL vet -tags $set"; ok=0
  elif [[ "$vet_only" -eq 0 ]]; then
    mapfile -t pkgs < <(tagged_pkgs "$set")
    full=() heavy=()
    for p in "${pkgs[@]}"; do
      if [[ -z "$run" ]] && ! is_edition "$set" && is_heavy "$p"; then heavy+=("$p"); else full+=("$p"); fi
    done
    if [[ ${#full[@]} -gt 0 ]]; then
      args=(-count=1 -tags "$set")
      [[ -n "$run" ]] && args+=(-run "$run")
      if ! go test "${args[@]}" "${full[@]}"; then
        echo "FAIL test -tags $set"; ok=0
      fi
    fi
    for p in "${heavy[@]}"; do
      names="$(tagged_tests "$set" "$p")"
      if [[ -n "$names" ]]; then
        echo "heavy package $p: only its tagged tests (${names//|/ })"
        hrun="^(${names})\$"
      else
        echo "heavy package $p: compile only (no tagged test)"
        hrun='^$'
      fi
      if ! go test -count=1 -tags "$set" -run "$hrun" "$p"; then
        echo "FAIL test -tags $set $p"; ok=0
      fi
    done
  fi
  [[ "$gh" -eq 1 ]] && echo "::endgroup::"
  if [[ "$ok" -eq 0 ]]; then
    fail=1; failed+=("$set")
    [[ "$gh" -eq 1 ]] && echo "::error::omit-tag set failed: $set"
  fi
done
if [[ "$fail" -ne 0 ]]; then
  echo "omit-tag-check: ${#failed[@]} of ${#sets[@]} set(s) failed:" >&2
  printf '  %s\n' "${failed[@]}" >&2
fi
exit "$fail"
