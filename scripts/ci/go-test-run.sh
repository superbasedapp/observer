#!/usr/bin/env bash
# go-test-run.sh <index> <count> - run one CI test shard (D-609).
#
# The shard's packages come from go-test-shards.sh (narrowed by SHARD_FILTER
# when the push tests only affected packages). They are split by RACE_FILTER,
# a file of module-relative paths written by scripts/ci/cipkgs race:
#   the listed packages run with -race, the rest without. A push and a full
#   run (workflow_dispatch, the release gate) use the same list; a full run
#   whose go.mod or go.sum changed since the previous release lists every
#   package (cipkgs race --since). RACE_FILTER unset: the list is computed
#   here (cipkgs race). A file holding the single word ALL: cipkgs race
#   --all. tests/invariant is on no list (cipkgs neverRace).
#
# Result replay (push tier only): with GO_TEST_REPLAY=1 the packages that
# are not on FRESH_FILTER (a file written by scripts/ci/cipkgs fresh; unset:
# computed here) run without -count=1, so Go may replay a cached result of
# an unchanged package. FRESH_FILTER packages (end-to-end suites, live
# database and LIVE-switch packages) always run with -count=1. Without
# GO_TEST_REPLAY=1 every package runs with -count=1: workflow_dispatch and
# the release gate never replay a result.
#
# Every non-empty half runs, so one failing half does not hide another.
#
# Split units (lane CICD, 2026-11-01): a package on scripts/ci/go-test-splits.tsv
# reaches the shard as <import>#<i>/<k> units. Each runs as its own go test of
# that package with the -run / -skip selector from `cipkgs split`, beside the
# package batches, and takes the package's -race and -count=1 decisions.
#
# Prebuilt observer (TESTSLOW item 16): when the shard holds an end-to-end
# suite that reads SBO_E2E_OBSERVER_BIN (found by grepping tests/e2e, not a
# hand list) and the variable is unset, observer is built once for the job
# and the variable set, so those suites share one build instead of each
# running go build ./cmd/observer. Each suite logs the path and mtime.
#
# -gcflags turns checkptr off for modernc.org/... only (D-604); the race
# detector still instruments it.
set -euo pipefail
export LC_ALL=C

index="${1:?index}" count="${2:?count}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

module="$(go list -m)"
read -r -a pkgs <<<"$("${script_dir}/go-test-shards.sh" list "${index}" "${count}")"
if [[ ${#pkgs[@]} -eq 0 ]]; then
  echo "::notice::shard ${index} of ${count} has no packages"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

race_list="${tmp}/race.txt"
if [[ -z "${RACE_FILTER:-}" ]]; then
  go run ./scripts/ci/cipkgs race >"${race_list}"
elif grep -qx 'ALL' "${RACE_FILTER}"; then
  go run ./scripts/ci/cipkgs race --all >"${race_list}"
else
  cp "${RACE_FILTER}" "${race_list}"
fi

fresh_list="${tmp}/fresh.txt"
replay=0
if [[ "${GO_TEST_REPLAY:-0}" == "1" ]]; then
  replay=1
  if [[ -n "${FRESH_FILTER:-}" ]]; then
    cp "${FRESH_FILTER}" "${fresh_list}"
  else
    go run ./scripts/ci/cipkgs fresh >"${fresh_list}"
  fi
fi

# The lists hold module-relative paths; the shard lists import paths.
declare -A race_want=() fresh_want=()
while IFS= read -r l; do
  [[ -z "$l" ]] && continue
  if [[ "$l" == "." ]]; then race_want["${module}"]=1; else race_want["${module}/${l}"]=1; fi
done <"${race_list}"
if [[ "${replay}" -eq 1 ]]; then
  while IFS= read -r l; do
    [[ -z "$l" ]] && continue
    if [[ "$l" == "." ]]; then fresh_want["${module}"]=1; else fresh_want["${module}/${l}"]=1; fi
  done <"${fresh_list}"
fi

race_fresh=() race_replay=() plain_fresh=() plain_replay=() split_units=()
for p in "${pkgs[@]}"; do
  # A split unit (<import>#<i>/<k>, scripts/ci/go-test-splits.tsv) runs on
  # its own below; it takes its package's -race and -count=1 decision.
  if [[ "$p" == *"#"* ]]; then
    split_units+=("$p")
    continue
  fi
  fresh=1
  [[ "${replay}" -eq 1 && -z "${fresh_want[$p]:-}" ]] && fresh=0
  if [[ -n "${race_want[$p]:-}" ]]; then
    if [[ "${fresh}" -eq 1 ]]; then race_fresh+=("$p"); else race_replay+=("$p"); fi
  else
    if [[ "${fresh}" -eq 1 ]]; then plain_fresh+=("$p"); else plain_replay+=("$p"); fi
  fi
done

if [[ -z "${SBO_E2E_OBSERVER_BIN:-}" ]]; then
  declare -A e2e_want=()
  while IFS= read -r d; do
    [[ -n "$d" ]] && e2e_want["${module}/${d}"]=1
  done < <(git grep -l 'SBO_E2E_OBSERVER_BIN' -- 'tests/e2e/*_test.go' | xargs -r -n1 dirname | sort -u)
  for p in "${pkgs[@]}"; do
    if [[ -n "${e2e_want[${p%%#*}]:-}" ]]; then
      bin="${tmp}/observer"
      [[ "$(go env GOOS)" == "windows" ]] && bin="${bin}.exe"
      echo "shard ${index}/${count}: building observer once for the end-to-end suites (${bin})"
      go build -o "${bin}" ./cmd/observer
      export SBO_E2E_OBSERVER_BIN="${bin}"
      break
    fi
  done
fi

# run_split_units runs every split unit of the shard, one go test each, in
# order. A unit is one part of a package's tests: the flag from cipkgs split
# selects it (-run for an earlier part, -skip of every earlier part for the
# last one), so the k parts of a package cover it exactly once.
run_split_units() {
  local u pkg spec i k rel flag urc=0
  local -a args
  for u in "${split_units[@]}"; do
    pkg="${u%%#*}" spec="${u#*#}"
    i="${spec%/*}" k="${spec#*/}"
    if [[ "${pkg}" == "${module}" ]]; then rel="."; else rel="${pkg#"${module}"/}"; fi
    flag="$(go run ./scripts/ci/cipkgs split "${rel}" "${i}" "${k}")" || { echo "::error::cipkgs split ${rel} ${i} ${k} failed"; urc=1; continue; }
    args=(-timeout 90m)
    if [[ -n "${race_want[$pkg]:-}" ]]; then args+=(-race -gcflags='modernc.org/...=-d=checkptr=0'); fi
    if [[ "${replay}" -eq 0 || -n "${fresh_want[$pkg]:-}" ]]; then args+=(-count=1); fi
    [[ -n "${flag}" ]] && args+=("${flag}")
    echo "split unit ${u}: go test ${args[*]:0:4} ... (${#flag}-byte selector)"
    go test "${args[@]}" "${pkg}" || urc=1
  done
  return "${urc}"
}

echo "shard ${index}/${count}: $(( ${#race_fresh[@]} + ${#race_replay[@]} )) package(s) with -race, $(( ${#plain_fresh[@]} + ${#plain_replay[@]} )) without; $(( ${#race_replay[@]} + ${#plain_replay[@]} )) may replay a cached result; ${#split_units[@]} split unit(s)"
rc=0
# The split units run beside the package batches (in the background, their
# log printed when they finish) so the shard's cores stay busy the way they
# did when the whole package ran inside a batch.
split_pid=""
if [[ ${#split_units[@]} -gt 0 ]]; then
  run_split_units >"${tmp}/split.log" 2>&1 &
  split_pid=$!
fi
if [[ ${#race_fresh[@]} -gt 0 ]]; then
  go test -race -count=1 -gcflags='modernc.org/...=-d=checkptr=0' -timeout 90m "${race_fresh[@]}" || rc=1
fi
if [[ ${#race_replay[@]} -gt 0 ]]; then
  go test -race -gcflags='modernc.org/...=-d=checkptr=0' -timeout 90m "${race_replay[@]}" || rc=1
fi
if [[ ${#plain_fresh[@]} -gt 0 ]]; then
  go test -count=1 -timeout 90m "${plain_fresh[@]}" || rc=1
fi
if [[ ${#plain_replay[@]} -gt 0 ]]; then
  go test -timeout 90m "${plain_replay[@]}" || rc=1
fi
if [[ -n "${split_pid}" ]]; then
  wait "${split_pid}" || rc=1
  echo "---- split units (${#split_units[@]}) ----"
  cat "${tmp}/split.log"
fi
exit "${rc}"
