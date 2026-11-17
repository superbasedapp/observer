#!/usr/bin/env bash
# omit-tag-check.sh: vet and test every build-tag variant the tree actually
# has, so an off file cannot rot unnoticed (modular packaging plan 5.9 and
# risk R1, "stub rot"; lane MP-REL).
#
#   scripts/omit-tag-check.sh [--vet-only] [--run <regex>] [--list | --list-tests]
#                              [--only <set>]
#                              [--scope distro | --scope narrow --tags <a,b>]
#                              [--batch <i>/<n>]
#
# The tag set is read from the tree, never from a list in this script: every
# sbo_omit_* tag named in a //go:build line, the one-release alias no_obs,
# and the tag set of every stamped distro (sbo-components distros, then
# sbo-components tags, which add the sbo_distro_* stamps). For each one:
#
#   go vet -tags <tags> ./...                 (every package, tests included:
#                                              vet type-checks every test file)
#   go test -tags <tags> <tagged packages>    (editions only: the packages
#                                              holding a file whose build
#                                              line names a tag in the set;
#                                              --run narrows them)
#
# The four published editions (no_obs and the three distro sets) run the
# full tests of every tagged package. Every other set (a single sbo_omit_*
# tag, custom-build.yml only) runs go vet only, which still compiles and
# type-checks every package and test file under the tag, so a stub that no
# longer matches its counterpart fails (operator decision "Vet only",
# 2026-11-01: the single sets' tests cost about 80 minutes of a full run
# and the editions are what the release publishes).
#
# A tag no file names cannot change what compiles, so it is skipped: its
# build is the default build, which the ordinary CI jobs already cover.
# --scope distro keeps only the distro sets and no_obs (the editions
# npm-release publishes); --scope narrow --tags <comma list> keeps those
# plus the single sets named in the list (a P-222 narrowed release-gate run:
# the tags `cipkgs narrow` found in the diff's dependency closure; a listed
# tag that is no set of this tree is ignored); --batch i/n keeps batch i (0-based) of an n-way
# split balanced by measured time (scripts/ci/omit-tag-weights.tsv, LPT).
# Each set prints as a log group; a failing set is named and the run goes on.
# ci.yml runs --scope distro per push and the full list in 6 batches on a
# dispatched full run and a tag push (D-609). On a small host use --vet-only or --run.
#
# --list prints the sets. --list-tests prints the same sets, each on a line
# of its own, and after each edition one line per package its tests run:
# <set> TAB ./<dir>. tools/testrunner's gate reads it to run each set as
# `--vet-only --only <set>` and each edition package's tests as a Go unit of
# its own with -tags <set>: the same go vet and go test this script runs,
# split so they spread over workers. Without either flag nothing changes.
set -euo pipefail

vet_only=0 run="" list=0 list_tests=0 only="" scope="" batch="" tags=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vet-only) vet_only=1; shift ;;
    --run) run="$2"; shift 2 ;;
    --list) list=1; shift ;;
    --list-tests) list_tests=1; shift ;;
    --only) only="$2"; shift 2 ;;
    # --scope distro: only the distro sets (sbo_distro_* stamp) and no_obs,
    # the editions npm-release publishes. ci.yml runs these on every push.
    --scope) scope="$2"; shift 2 ;;
    # --tags <comma list>: the single sets --scope narrow adds to the editions.
    --tags) tags="$2"; shift 2 ;;
    # --batch <i>/<n>: batch i (0-based) of an n-way split balanced by the
    # measured seconds per set, so CI runs the full list in n jobs that each
    # share one warm build cache (D-609) and end at about the same time.
    --batch) batch="$2"; shift 2 ;;
    *) sed -n '2,/^set -euo pipefail$/{/^set /d;p}' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
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
  narrow)
    kept=()
    for s in "${sets[@]}"; do
      if [[ "$s" == "no_obs" || ",$s" == *",sbo_distro_"* || ",${tags}," == *",$s,"* ]]; then kept+=("$s"); fi
    done
    sets=("${kept[@]}")
    ;;
  *) echo "omit-tag-check: --scope must be distro or narrow" >&2; exit 2 ;;
esac
if [[ -n "$batch" ]]; then
  if [[ ! "$batch" =~ ^([0-9]+)/([0-9]+)$ ]] || (( BASH_REMATCH[2] < 1 || BASH_REMATCH[1] >= BASH_REMATCH[2] )); then
    echo "omit-tag-check: --batch wants <i>/<n> with 0 <= i < n" >&2
    exit 2
  fi
  bi=${BASH_REMATCH[1]} bn=${BASH_REMATCH[2]}
  # Longest-processing-time-first over the measured seconds per set
  # (scripts/ci/omit-tag-weights.tsv; a distro set keyed by its
  # sbo_distro_* stamp, an unlisted set 120 s): heaviest first, ties by
  # name, each to the batch with the least so far (ties to the lowest
  # index). Deterministic, so the n batch jobs agree, and a partition
  # whatever the weights say: every set lands in exactly one batch.
  mapfile -t kept < <(printf '%s\n' "${sets[@]}" | awk -v weights="scripts/ci/omit-tag-weights.tsv" '
      BEGIN {
        FS = "\t"
        while ((getline line < weights) > 0) {
          if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
          split(line, f, "\t"); if (f[1] != "" && f[2] + 0 > 0) w[f[1]] = f[2] + 0
        }
      }
      {
        key = $0
        if (match($0, /sbo_distro_[A-Za-z0-9_]+/)) key = substr($0, RSTART, RLENGTH)
        printf "%d\t%s\n", ((key in w) ? w[key] : 120), $0
      }' \
    | LC_ALL=C sort -t "$(printf '\t')" -k1,1nr -k2,2 \
    | awk -F '\t' -v n="$bn" -v want="$bi" '
      { best = 0; for (i = 1; i < n; i++) if (tot[i] < tot[best]) best = i
        tot[best] += $1; if (best == want) print $2 }')
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

# is_edition <set>: true for the editions npm-release publishes (the same
# rule as --scope distro).
is_edition() {
  [[ "$1" == "no_obs" || ",$1" == *",sbo_distro_"* ]]
}

# --list-tests: the edition packages this run would test, per set.
if [[ "$list_tests" -eq 1 ]]; then
  for set in "${sets[@]}"; do
    printf '%s\n' "$set"
    is_edition "$set" || continue
    tagged_pkgs "$set" | while read -r p; do printf '%s\t%s\n' "$set" "$p"; done
  done
  exit 0
fi

fail=0 failed=()
# In GitHub Actions each set is a collapsible log group, so a batch job still
# shows one failure line per set.
gh=0; [[ -n "${GITHUB_ACTIONS:-}" ]] && gh=1
for set in "${sets[@]}"; do
  if [[ "$gh" -eq 1 ]]; then echo "::group::tags: $set"; else echo "== tags: $set"; fi
  ok=1
  if ! go vet -tags "$set" ./...; then
    echo "FAIL vet -tags $set"; ok=0
  elif [[ "$vet_only" -eq 0 ]] && is_edition "$set"; then
    mapfile -t pkgs < <(tagged_pkgs "$set")
    if [[ ${#pkgs[@]} -gt 0 ]]; then
      args=(-count=1 -timeout 90m -tags "$set")
      [[ -n "$run" ]] && args+=(-run "$run")
      if ! go test "${args[@]}" "${pkgs[@]}"; then
        echo "FAIL test -tags $set"; ok=0
      fi
    fi
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
