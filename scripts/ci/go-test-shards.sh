#!/usr/bin/env bash
# go-test-shards.sh - deterministically split the Go test-package universe into
# N balanced shards so CI can run `go test -race` in parallel jobs.
#
# Why this exists: ci.yml's `go` job ran the whole race suite as ONE step
# (`go test -race -timeout 40m ./...`). By 2026-09-16 that step took 5+ hours on
# the 2-core private-repo runner and hit GitHub's hard 6 h job cap on three
# consecutive pushes - the job was killed with no useful signal, so CI stopped
# being a gate at all. Splitting the suite across matrix shards puts every
# shard under a 120 min job timeout, and a failure now points at a package
# instead of at a stopwatch. The shard count is not fixed: ci.yml's plan job
# sizes it per run with `plan <max> <target>` (1 to 12 shards, D-609).
#
# The assignment is a plain LPT (longest-processing-time-first) greedy:
#   sort packages by weight DESC, then import path ASC (stable + reproducible),
#   then hand each package to whichever shard currently has the lowest running
#   total (ties -> lowest shard index).
# Because the input order is total and the rule is deterministic, every runner
# computes the same assignment from the same checkout and the same SHARD_FILTER
# file (which ci.yml's plan job hands every shard as the test-plan artifact) -
# no other coordination between jobs.
#
# Weights come from scripts/ci/go-test-weights.tsv (module-relative path TAB
# integer seconds). They are a BALANCING HEURISTIC ONLY. A package missing from
# the table gets a default weight, and a stale table makes the shards uneven -
# it can never make a package disappear, because the package universe is
# recomputed from `go list` on every invocation. That correctness property is
# what `check` asserts in CI.
#
# Modes:
#   list <index> <count>     space-separated import paths for one shard (stdout,
#                            nothing else - scripts/ci/go-test-run.sh reads it
#                            and splits it into its -race and plain halves).
#                            A package on scripts/ci/go-test-splits.tsv is
#                            listed as <import>#<i>/<k> units instead, each
#                            1/k of its weight (scheduled like packages; the
#                            run script turns a unit into a -run or -skip of
#                            that package's tests).
#   plan <max> <target>      how many shards (1..max) the filtered universe
#                            needs to stay near <target> package-seconds each
#   check <count>            run the whole assignment, assert union == universe
#                            (with every split package's k units), no
#                            duplicates, no empty shard; print a per-shard
#                            summary. This is the honesty gate: a sharder bug
#                            that silently drops a package turns into a red job
#                            rather than into a test that stopped running.
#   weights <job-log-file>   regenerate the weight table from a real GitHub
#                            Actions job log:
#                              scripts/ci/go-test-shards.sh weights job.log \
#                                > scripts/ci/go-test-weights.tsv
#
# Pure bash + awk + sort + go. No python, no jq (the runner image is not
# guaranteed to carry either for this job).
set -euo pipefail

export LC_ALL=C

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
weights_file="${script_dir}/go-test-weights.tsv"
splits_file="${script_dir}/go-test-splits.tsv"

# Weight given to a package that is not in the table (a brand-new package, or
# one that was added after the table was last regenerated). Small on purpose:
# an unknown package is much more likely to be a fresh, fast one than another
# internal/store, and under-weighting only costs balance.
default_weight=5

usage() {
  cat >&2 <<'EOF'
usage:
  go-test-shards.sh list <index> <count>     print shard <index> of <count> (0-based), space-separated
  go-test-shards.sh check <count>            verify the <count>-way split covers the universe exactly
  go-test-shards.sh weights <job-log-file>   regenerate the weight TSV from a GitHub Actions job log
  go-test-shards.sh plan <max> <target-secs> how many shards the (filtered) universe needs
EOF
  exit 2
}

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

# module_path prints the Go module path, e.g. github.com/marmutapp/superbased-observer.
module_path() {
  (cd "${repo_root}" && go list -m)
}

# universe prints one full import path per line for every package that has any
# test file - internal test files (TestGoFiles) OR external ones (XTestGoFiles).
# The XTestGoFiles half matters: ~31 packages in this tree carry only a
# `package foo_test` file, and a TestGoFiles-only filter would silently drop
# every one of them.
#
# SHARD_FILTER (D-609): a file of module-relative package paths, one per line
# (scripts/ci/cipkgs affected output). When set and the file is not the single
# word ALL, the universe is narrowed to those packages, so a push tests only
# what it can affect. Unset, or ALL, keeps the whole universe.
universe() {
  local all
  all="$( (cd "${repo_root}" && go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...) |
    grep -v '^$' || true)"
  if [[ -n "${SHARD_FILTER:-}" ]] && ! grep -qx 'ALL' "${SHARD_FILTER}"; then
    local module
    module="$(module_path)"
    printf '%s
' "${all}" | awk -v module="${module}" -v filter="${SHARD_FILTER}" '
      BEGIN { while ((getline l < filter) > 0) { if (l == ".") keep[module] = 1; else if (l != "") keep[module "/" l] = 1 } }
      ($0 in keep)'
  else
    printf '%s
' "${all}"
  fi
}

# units emits "<weight>\t<unit>" for every package in the universe: the
# import path, or for a package on the split table its k units
# <import>#<i>/<k>, each carrying ceil(weight / k).
units() {
  local module
  module="$(module_path)"

  universe | awk -v weights="${weights_file}" \
                 -v splits="${splits_file}" \
                 -v module="${module}" \
                 -v defw="${default_weight}" '
    BEGIN {
      FS = "\t"
      prefix = module "/"
      plen = length(prefix)
      while ((getline line < weights) > 0) {
        if (line ~ /^[ \t]*#/) continue
        if (line ~ /^[ \t]*$/) continue
        split(line, f, "\t")
        key = f[1]
        val = f[2] + 0
        if (key != "" && val > 0) w[key] = val
      }
      close(weights)
      while ((getline line < splits) > 0) {
        if (line ~ /^[ \t]*#/) continue
        if (line ~ /^[ \t]*$/) continue
        split(line, f, "\t")
        if (f[1] != "" && f[2] + 0 >= 2) parts[f[1]] = int(f[2] + 0)
      }
      close(splits)
    }
    {
      path = $0
      rel = path
      if (substr(path, 1, plen) == prefix) rel = substr(path, plen + 1)
      else if (path == module) rel = "."
      weight = (rel in w) ? w[rel] : defw
      if (rel in parts) {
        k = parts[rel]
        uw = int((weight + k - 1) / k)
        for (i = 0; i < k; i++) printf "%d\t%s#%d/%d\n", uw, path, i, k
      } else {
        printf "%d\t%s\n", weight, path
      }
    }
  '
}

# assign emits "<shard>\t<weight>\t<unit>" for every unit (units above), for
# a <count>-way split.
assign() {
  local count="$1"

  units | sort -t "$(printf '\t')" -k1,1nr -k2,2 | awk -v count="${count}" '
    BEGIN { FS = "\t"; for (i = 0; i < count; i++) total[i] = 0 }
    {
      best = 0
      for (i = 1; i < count; i++) if (total[i] < total[best]) best = i
      total[best] += $1
      printf "%d\t%d\t%s\n", best, $1, $2
    }
  '
}

cmd_list() {
  local index="$1" count="$2"
  is_uint "${index}" || usage
  is_uint "${count}" || usage
  [[ "${count}" -ge 1 ]] || usage
  [[ "${index}" -lt "${count}" ]] || {
    echo "go-test-shards: shard index ${index} out of range for ${count} shards" >&2
    exit 2
  }

  assign "${count}" | awk -v idx="${index}" -F "\t" '$1 == idx { printf "%s%s", sep, $3; sep = " " } END { if (sep != "") printf "\n" }'
}

cmd_check() {
  local count="$1"
  is_uint "${count}" || usage
  [[ "${count}" -ge 1 ]] || usage

  local tmp
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp}'" RETURN

  # The universe in units: a split package must appear as all k of its
  # units, so a lost part shows up as a '-' line like a lost package.
  units | cut -f2 | sort > "${tmp}/universe"
  assign "${count}" > "${tmp}/assigned"
  cut -f3 "${tmp}/assigned" | sort > "${tmp}/covered"

  local rc=0
  local n_universe n_assigned n_covered
  n_universe="$(grep -c . < "${tmp}/universe" || true)"
  n_assigned="$(grep -c . < "${tmp}/assigned" || true)"
  n_covered="$(sort -u < "${tmp}/covered" | grep -c . || true)"

  # (b) no package assigned twice.
  if [[ "${n_assigned}" -ne "${n_covered}" ]]; then
    echo "::error::go-test-shards: ${n_assigned} assignments cover only ${n_covered} distinct packages - a package landed in more than one shard."
    sort "${tmp}/covered" | uniq -d | head -20 >&2
    rc=1
  fi

  # (a) union == universe, both directions.
  if ! diff -u "${tmp}/universe" <(sort -u "${tmp}/covered") > "${tmp}/diff" 2>&1; then
    echo "::error::go-test-shards: shard union != test-package universe (${n_universe} packages in universe, ${n_covered} covered)."
    echo "::error::A '-' line is a package NO shard would run; a '+' line is a package no longer in the universe."
    head -40 "${tmp}/diff" >&2
    rc=1
  fi

  # (d) every split package is covered by all k of its parts, counted from
  # the plain universe and the split table independently of units():
  # <import>#0/k .. #k-1/k, each exactly once.
  local module bad_split
  module="$(module_path)"
  bad_split="$(universe | awk -v splits="${splits_file}" -v module="${module}" -v covered="${tmp}/covered" '
    BEGIN {
      FS = "\t"; prefix = module "/"; plen = length(prefix)
      while ((getline line < splits) > 0) {
        if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
        split(line, f, "\t"); if (f[1] != "" && f[2] + 0 >= 2) parts[f[1]] = int(f[2] + 0)
      }
      while ((getline line < covered) > 0) seen[line]++
    }
    {
      rel = (substr($0, 1, plen) == prefix) ? substr($0, plen + 1) : "."
      if (!(rel in parts)) { if (seen[$0] != 1) print $0 " covered " (seen[$0] + 0) " times"; next }
      for (i = 0; i < parts[rel]; i++) {
        u = $0 "#" i "/" parts[rel]
        if (seen[u] != 1) print u " covered " (seen[u] + 0) " times"
      }
    }')"
  if [[ -n "${bad_split}" ]]; then
    echo "::error::go-test-shards: a package or split part is not covered exactly once:"
    echo "${bad_split}" | head -20 >&2
    rc=1
  fi

  # (c) no empty shard.
  local i n est
  for ((i = 0; i < count; i++)); do
    n="$(awk -F "\t" -v idx="${i}" '$1 == idx { c++ } END { print c + 0 }' "${tmp}/assigned")"
    est="$(awk -F "\t" -v idx="${i}" '$1 == idx { s += $2 } END { print s + 0 }' "${tmp}/assigned")"
    printf 'shard %d: %d packages, est %ds\n' "${i}" "${n}" "${est}"
    if [[ "${n}" -eq 0 ]]; then
      echo "::error::go-test-shards: shard ${i} of ${count} is empty - reduce the shard count."
      rc=1
    fi
  done

  printf 'total: %d packages across %d shards\n' "${n_universe}" "${count}"
  return "${rc}"
}

# cmd_plan prints how many shards (1..max) the current universe (after
# SHARD_FILTER) needs so each stays near <target> package-seconds. Packages not
# in RACE_FILTER (a file of module-relative paths, or ALL) run without -race
# and count a quarter of their (race-measured) weight.
cmd_plan() {
  local max="$1" target="$2"
  is_uint "${max}" || usage
  is_uint "${target}" || usage
  local module
  module="$(module_path)"
  universe | awk -v weights="${weights_file}" -v module="${module}" -v defw="${default_weight}"       -v race="${RACE_FILTER:-}" -v max="${max}" -v target="${target}" '
    BEGIN {
      FS = "	"; prefix = module "/"; plen = length(prefix); all = (race == "")
      while ((getline line < weights) > 0) {
        if (line ~ /^[ 	]*#/ || line ~ /^[ 	]*$/) continue
        split(line, f, "	"); if (f[1] != "" && f[2] + 0 > 0) w[f[1]] = f[2] + 0
      }
      if (!all) { while ((getline l < race) > 0) { if (l == "ALL") all = 1; else if (l != "") r[l] = 1 } }
    }
    {
      rel = (substr($0, 1, plen) == prefix) ? substr($0, plen + 1) : "."
      x = (rel in w) ? w[rel] : defw
      if (!all && !(rel in r)) x = x / 4
      sum += x; n++
    }
    END {
      if (n == 0) { print 0; exit }
      c = int((sum + target - 1) / target); if (c < 1) c = 1; if (c > max) c = max; if (c > n) c = n
      print c
    }'
}

cmd_weights() {
  local log="$1"
  [[ -f "${log}" ]] || {
    echo "go-test-shards: no such job log: ${log}" >&2
    exit 2
  }
  local module
  module="$(module_path)"

  # GitHub prefixes every log line with an RFC3339 timestamp, so the go test
  # summary lines look like:
  #   2026-09-10T11:15:20.1670919Z ok  <TAB>github.com/<module>/cmd/x<TAB>1.013s
  #   2026-09-10T11:30:48.3300031Z FAIL<TAB>github.com/<module>/cmd/observer<TAB>826.979s
  # A "[no test files]" line carries no duration and is skipped. A FAIL line DOES
  # carry one and is kept - a failing package still costs a shard that time.
  awk -v module="${module}" '
    BEGIN {
      prefix = module "/"
      plen = length(prefix)
    }
    /no test files/ { next }
    {
      # Find the "ok"/"FAIL" verdict, the import path and the duration anywhere
      # on the line (fields are tab-separated after the timestamp prefix).
      n = split($0, f, /[ \t]+/)
      for (i = 1; i < n; i++) {
        if (f[i] != "ok" && f[i] != "FAIL") continue
        path = f[i + 1]
        dur = f[i + 2]
        if (substr(path, 1, plen) != prefix) continue
        if (dur !~ /^[0-9]+(\.[0-9]+)?s$/) continue
        rel = substr(path, plen + 1)
        secs = substr(dur, 1, length(dur) - 1) + 0
        secs = int(secs + 0.5)
        if (secs < 1) secs = 1
        if (!(rel in seen) || secs > seen[rel]) seen[rel] = secs
        break
      }
    }
    END {
      for (rel in seen) printf "%s\t%d\n", rel, seen[rel]
    }
  ' "${log}" | sort -t "$(printf '\t')" -k1,1
}

main() {
  [[ $# -ge 1 ]] || usage
  local mode="$1"
  shift
  case "${mode}" in
    list)
      [[ $# -eq 2 ]] || usage
      cmd_list "$1" "$2"
      ;;
    check)
      [[ $# -eq 1 ]] || usage
      cmd_check "$1"
      ;;
    weights)
      [[ $# -eq 1 ]] || usage
      cmd_weights "$1"
      ;;
    plan)
      [[ $# -eq 2 ]] || usage
      cmd_plan "$1" "$2"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
