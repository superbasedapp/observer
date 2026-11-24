#!/usr/bin/env bash
# gate-record.sh: the one gate record per commit (operator ruling L-145).
#
# A gate record is the evidence that a full gate of one commit passed: every
# unit the gate schedules and every host check green, for that exact commit.
# It is unsigned. It lives on origin as refs/gate-records/<sha>, a commit
# whose tree is exactly record.json, ledger.snapshot.tsv and reports.txt; the
# first publish is a commit with no parent, and adding the release's image
# ids makes a child commit, so the ref's history shows what was added when.
# Anyone who can push that ref can make GitHub skip the covered jobs of the
# commit, so the record is as trustworthy as push access to origin. GitHub
# skips the jobs in scripts/ci/gate-coverage.tsv on `check`'s gated=true, and
# production rolls a release's images only when the record of its commit
# lists their ids. Design: docs/plans/ci-github-only-what-needs-github-
# 2026-11-21.md section 11 (the shard report, 9.2; `gatedriver reports`, 9.4).
#
#   build <sha> [--no-push] [--force] [--omit-scope all|distro]
#               [--adopt-legacy] [--runner <testrunner>]
#               [--gatedriver <gatedriver>]
#     Run on WSL or in a cloud session, in a clone whose origin holds the
#     shard reports. Fetches the report branches
#     claude/gate-results/<sha10>/<name> (refuses with none, or with one
#     whose tree has no gate-results/<name>/report.json), checks <sha> out
#     in a temporary worktree (removed on exit), lists there the units a
#     full gate of that commit schedules (`testrunner gate --full
#     --omit-scope <scope> --list-units` with a fresh --home), extracts each
#     branch's gate-results/<name>/ and runs `gatedriver reports` over them,
#     then publishes the record (see above). --no-push builds the record
#     commit, prints its id and stops. A published record is never replaced
#     without --force, and then the new commit's parent is the old one.
#     --omit-scope all (the default) is the release gate: a record of scope
#     release, the only scope GitHub skips jobs on; it requires the
#     candidate's scripts/ci/gate-host-checks.tsv. --omit-scope distro is
#     the editions-only gate: a record of scope gate, which production
#     accepts and GitHub never skips on; no host check is expected of it.
#     The testrunner and gatedriver run in the candidate's worktree, by
#     default `go run ./tools/testrunner` and `go run ./tools/gatedriver`
#     from the candidate's own tree. A commit older than `testrunner gate
#     --list-units` and `gatedriver reports` needs binaries built from a
#     newer checkout: --runner <path> and --gatedriver <path>, or
#     $TESTRUNNER and $GATEDRIVER (a command line, split on spaces).
#     --adopt-legacy also takes report branches in the layout used before
#     gate-shard.sh (a commit holding gate-results/<dir>/ledger.tsv, with
#     summary.md and env.txt beside it, and no report.json): the ledger is
#     copied unchanged and a report.json is derived from it (shard from the
#     branch name, shard-<i>-of-<n> or rerun-<name>; scope and omit scope
#     from --omit-scope, which the person running build asserts for those
#     runs; verdict GATE FAIL when a unit's latest row of <sha> is not green;
#     host class wsl when env.txt, or with no env.txt summary.md, mentions
#     WSL, else cloud). reports.txt names each adopted branch and its commit.
#     A failed row that a later row of another report passed (a rerun-<name>
#     report of the failed units) is accepted and listed in reports.txt
#     (gatedriver reports, rule 4).
#
#   check [<sha>] [--any-scope]
#     GitHub's question, asked by each workflow's first job: prints
#     gated=true or gated=false, appends the same line to $GITHUB_OUTPUT
#     when it is set, and explains on stderr. It never fails (exit 0) and
#     answers false on any doubt (no record, another commit, a failed or
#     partial gate, a malformed record, no jq). true needs version 1, this
#     sha, mode full, verdict GATE PASS, scope release, units_pass >=
#     $GATE_RECORD_MIN_UNITS (default 500), units_expected > 0 and
#     units_pass + units_env_known >= units_expected. --any-scope also
#     accepts scope gate (the release pipeline's question before it adds the
#     image ids: production accepts either scope). Needs only git and jq.
#     <sha> defaults to $GITHUB_SHA.
#
#   add-images <sha> <name>=<id>[@<ref>] ... [--source ops-vm-build]
#              [--gatedriver <gatedriver>]
#     Adds image ids to the published record through `gatedriver
#     add-images` and pushes a child commit (fast-forward only; a record
#     that moved meanwhile is refused, run it again). <id> is the
#     linux/amd64 image id a host compares after `docker load`, <ref> the
#     registry reference by index digest. An image with no registry copy
#     (built on the ops VM by build-image.sh from a git archive of <sha>,
#     moved to the hosts as a `docker save` tar) is given as <name>=<id>
#     with --source ops-vm-build, the one build source a record knows; it
#     is recorded with that source and no reference, never an invented one.
#     A record that already lists them is left alone.
#
#   show <sha>
#     Prints the published record.json.
#
# Exit codes: 0 done; 2 usage; 3 refused (nothing published); anything else
# is the failing command's own.
set -uo pipefail

prog=gate-record
remote=origin

note() { echo "$prog: $*" >&2; }
die() {
  echo "$prog: $*" >&2
  exit 3
}
usage() {
  sed -n '/^#   build /,/^# is the failing/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

is_sha() { [[ $1 =~ ^[0-9a-f]{40}$ ]]; }

# record_verdict <file> <sha> <scopes json> <min units>: prints "ok", or the
# first reason the record is not a complete passing gate of <sha> (nothing
# when the file is not JSON). The one definition of a good record, for check
# and for build's closing summary.
record_verdict() {
  jq -r --arg sha "$2" --argjson scopes "$3" --argjson min "$4" '
    def num(f): (f | type) == "number";
    if type != "object" then "record.json is not a JSON object"
    elif .version != 1 then "version \(.version | tojson), want 1"
    elif .sha != $sha then "it is the record of \(.sha | tojson), not of \($sha)"
    elif .mode != "full" then "mode \(.mode | tojson), want \"full\""
    elif .verdict != "GATE PASS" then "verdict \(.verdict | tojson), want \"GATE PASS\""
    elif (.scope as $s | $scopes | any(.[]; . == $s) | not) then "scope \(.scope | tojson), want \($scopes | join(" or "))"
    elif (num(.units_pass) and num(.units_expected) and num(.units_env_known // 0)) | not then "units_pass, units_env_known or units_expected is not a number"
    elif .units_pass < $min then "\(.units_pass) passing units, fewer than \($min)"
    elif .units_expected <= 0 then "units_expected \(.units_expected), want more than 0"
    elif .units_pass + (.units_env_known // 0) < .units_expected then "\(.units_pass) pass + \(.units_env_known // 0) env_known cover fewer than the \(.units_expected) expected units"
    else "ok" end' "$1" 2>/dev/null
}

# ---------------------------------------------------------------- check

answer() {
  echo "gated=$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "gated=$1" >>"$GITHUB_OUTPUT"; fi
  echo "$prog: $2" >&2
  exit 0
}

cmd_check() {
  local sha="" scopes='["release"]' a
  for a in "$@"; do
    case $a in
      --any-scope) scopes='["release","gate"]' ;;
      *)
        if [ -n "$sha" ]; then answer false "unexpected argument '$a'; every job runs here"; fi
        sha=$a
        ;;
    esac
  done
  sha=${sha:-${GITHUB_SHA:-}}
  local min=${GATE_RECORD_MIN_UNITS:-500}
  is_sha "$sha" || answer false "no full commit sha given; every job runs here"
  [[ $min =~ ^[0-9]+$ ]] || answer false "GATE_RECORD_MIN_UNITS='$min' is not a number; every job runs here"
  if ! command -v git >/dev/null || ! command -v jq >/dev/null; then answer false "git or jq missing; every job runs here"; fi

  local ref="refs/gate-records/$sha" depth=()
  # A shallow clone (GitHub's checkout) fetches the record alone; a full
  # clone (a developer's, release.sh's) fetches its few commits rather than
  # gaining a .git/shallow entry for them.
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then depth=(--depth=1); fi
  git fetch --quiet --no-tags ${depth[@]+"${depth[@]}"} "$remote" "+$ref:$ref" 2>/dev/null ||
    answer false "no gate record for $sha ($ref on $remote); every job runs here"
  local tmp
  tmp=$(mktemp -d) || answer false "mktemp failed; every job runs here"
  # shellcheck disable=SC2064 # expand now: tmp is local to this function
  trap "rm -rf '$tmp'" EXIT
  git show "$ref:record.json" >"$tmp/record.json" 2>/dev/null ||
    answer false "$ref has no record.json; every job runs here"
  local why
  why=$(record_verdict "$tmp/record.json" "$sha" "$scopes" "$min")
  [ -n "$why" ] || why="record.json is not valid JSON"
  [ "$why" = ok ] || answer false "the gate record of $sha is not a complete passing gate of it: $why; every job runs here"
  answer true "$(jq -r '"a full gate passed \(.sha) (scope \(.scope), \(.units_pass) pass + \(.units_env_known // 0) env_known of \(.units_expected) expected units; \(.driver // "?"), \(.gated_at // "?")"' "$tmp/record.json"); the jobs in scripts/ci/gate-coverage.tsv are skipped"
}

# ---------------------------------------------------------------- helpers

tmp=""
ns=""
wt=""
cleanup() {
  # Only this run's worktree is removed; never `git worktree prune`, which
  # would also drop every other worktree whose path this OS cannot see (a
  # Windows worktree seen from WSL).
  if [ -n "$wt" ] && [ -d "$wt" ]; then
    git worktree remove --force "$wt" >/dev/null 2>&1 ||
      echo "$prog: could not remove the temporary worktree $wt; remove it with git worktree remove --force" >&2
  fi
  if [ -n "$ns" ]; then
    git for-each-ref --format='%(refname)' "$ns/" 2>/dev/null | while read -r r; do
      git update-ref -d "$r" >/dev/null 2>&1 || true
    done
  fi
  if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
}

setup() {
  git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"
  command -v jq >/dev/null || die "jq is required"
  local root
  root=$(git rev-parse --show-toplevel) || die "no work tree (a bare repository?)"
  cd "$root" || die "cannot cd to $root"
  tmp=$(mktemp -d) || die "mktemp failed"
  ns="refs/gate-record-tmp/$$-${RANDOM}"
  trap cleanup EXIT
  trap 'exit 130' INT TERM
}

# record_tip <sha>: prints the commit id of the published record of <sha>,
# nothing when there is none; refuses when origin cannot be asked.
record_tip() {
  local out rc
  out=$(git ls-remote --exit-code "$remote" "refs/gate-records/$1")
  rc=$?
  case $rc in
    0) printf '%s\n' "${out%%[[:space:]]*}" ;;
    2) ;;
    *) die "cannot list refs/gate-records/$1 on $remote (git ls-remote exit $rc)" ;;
  esac
}

# fetch_record <sha>: fetches the published record into the temporary
# namespace and prints that local ref; refuses when there is none.
fetch_record() {
  local tip
  tip=$(record_tip "$1") || exit $?
  [ -n "$tip" ] || die "no gate record for $1 (refs/gate-records/$1 on $remote)"
  git fetch --quiet --no-tags "$remote" "+refs/gate-records/$1:$ns/record" ||
    die "cannot fetch refs/gate-records/$1 from $remote"
  printf '%s\n' "$ns/record"
}

# ensure_ident: commit-tree needs an identity; a CI runner has none.
ensure_ident() {
  if ! git var GIT_COMMITTER_IDENT >/dev/null 2>&1 || ! git var GIT_AUTHOR_IDENT >/dev/null 2>&1; then
    export GIT_AUTHOR_NAME=gate-record GIT_AUTHOR_EMAIL=gate-record@localhost
    export GIT_COMMITTER_NAME=gate-record GIT_COMMITTER_EMAIL=gate-record@localhost
  fi
}

# record_commit <record blob> <ledger blob> <reports blob> <message> [parent]:
# writes the record commit (its tree exactly the three files) and prints its
# id.
record_commit() {
  local tree
  tree=$(printf '100644 blob %s\tledger.snapshot.tsv\n100644 blob %s\trecord.json\n100644 blob %s\treports.txt\n' \
    "$2" "$1" "$3" | git mktree) || die "git mktree failed"
  ensure_ident
  if [ -n "${5:-}" ]; then
    git commit-tree "$tree" -p "$5" -m "$4"
  else
    git commit-tree "$tree" -m "$4"
  fi
}

# push_record <sha> <commit>: a plain push, never forced. Creating the ref
# works once; afterwards only a child of the current tip is accepted, so a
# record that moved since it was read is refused, not overwritten.
push_record() {
  git push --quiet "$remote" "$2:refs/gate-records/$1" ||
    die "$remote refused refs/gate-records/$1 -> $2 (the record was published or changed meanwhile?); nothing replaced"
  note "refs/gate-records/$1 -> $2"
}

# split_cmd <var> <command line>: the words of a command line, into <var>.
split_cmd() {
  local -n _words=$1
  read -r -a _words <<<"$2"
}

# ---------------------------------------------------------------- build

# adopt_legacy <ref> <branch> <leaf> <sha> <scope> <dest>: writes the report
# directory <dest> from a report branch of the layout before gate-shard.sh
# (gate-results/<dir>/ledger.tsv, no report.json): the ledger unchanged,
# summary.md and env.txt when present, and report.json derived from them
# (contract 9.2). Prints the directory it read. Dies on anything else.
adopt_legacy() {
  local ref=$1 branch=$2 leaf=$3 sha=$4 scope=$5 dest=$6
  local dirs=() d shard rscope host_class=cloud f
  mapfile -t dirs < <(git ls-tree --name-only "$ref" gate-results/ 2>/dev/null)
  [ ${#dirs[@]} -eq 1 ] || die "report branch $branch: --adopt-legacy wants exactly one directory under gate-results/, found ${#dirs[@]}"
  d=${dirs[0]}
  git cat-file -e "$ref:$d/ledger.tsv" 2>/dev/null || die "report branch $branch has neither gate-results/$leaf/report.json nor $d/ledger.tsv"
  if [[ $leaf =~ ^shard-([1-9][0-9]*)-of-([1-9][0-9]*)$ ]]; then
    shard="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  elif [[ $leaf =~ ^rerun-[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    shard=rerun
  else
    die "report branch $branch: '$leaf' is neither shard-<i>-of-<n> nor rerun-<name>, so --adopt-legacy cannot name its shard"
  fi
  rscope=release
  [ "$scope" = all ] || rscope=gate
  mkdir -p "$dest"
  git show "$ref:$d/ledger.tsv" >"$dest/ledger.tsv" || die "cannot read $d/ledger.tsv from $branch"
  for f in summary.md env.txt; do
    if git cat-file -e "$ref:$d/$f" 2>/dev/null; then git show "$ref:$d/$f" >"$dest/$f"; fi
  done
  if [ -f "$dest/env.txt" ]; then
    if grep -qiE 'microsoft|wsl' "$dest/env.txt"; then host_class=wsl; fi
  elif [ -f "$dest/summary.md" ] && grep -qE 'WSL' "$dest/summary.md"; then
    host_class=wsl
  fi
  # The rows of <sha> (8 fields, file order) decide the derived fields.
  local rows="$tmp/adopt.rows"
  awk -F '\t' -v s="$sha" '!/^#/ && NF == 8 && $2 == s' "$dest/ledger.tsv" >"$rows"
  [ -s "$rows" ] || die "report branch $branch: $d/ledger.tsv has no row of $sha"
  local units runs verdict started finished
  units=$(awk -F '\t' '!seen[$1]++ { n++ } END { print n + 0 }' "$rows")
  runs=$(awk -F '\t' '$7 != "" && !seen[$7]++ { print $7 }' "$rows" | jq -R . | jq -s .)
  verdict=$(awk -F '\t' '{ r[$1] = $3 } END { v = "GATE PASS"; for (u in r) if (r[u] != "pass" && r[u] != "env_known") v = "GATE FAIL"; print v }' "$rows")
  started=$(cut -f6 "$rows" | sort | head -1)
  finished=$(cut -f6 "$rows" | sort | tail -1)
  jq -n --arg sha "$sha" --arg shard "$shard" --arg scope "$rscope" --arg omit "$scope" --arg hc "$host_class" \
    --arg verdict "$verdict" --argjson runs "$runs" --argjson units "$units" --arg st "$started" --arg fin "$finished" \
    '{version: 1, purpose: "sbo-gate-shard-report-v1", sha: $sha, shard: $shard, scope: $scope,
      omit_scope: $omit, host_class: $hc, verdict: $verdict, runs: $runs, units: $units,
      host_checks: [], started_at: $st, finished_at: $fin}' >"$dest/report.json" ||
    die "cannot derive report.json for $branch"
  echo "$d"
}

cmd_build() {
  local sha="" push=true force=false scope=all runner="" gdriver="" adopt=false
  while [ $# -gt 0 ]; do
    case $1 in
      --no-push) push=false ;;
      --force) force=true ;;
      --adopt-legacy) adopt=true ;;
      --omit-scope | --runner | --gatedriver)
        [ $# -ge 2 ] || usage
        case $1 in --omit-scope) scope=$2 ;; --runner) runner=$2 ;; --gatedriver) gdriver=$2 ;; esac
        shift
        ;;
      --omit-scope=*) scope=${1#*=} ;;
      --runner=*) runner=${1#*=} ;;
      --gatedriver=*) gdriver=${1#*=} ;;
      -*) usage ;;
      *)
        [ -z "$sha" ] || usage
        sha=$1
        ;;
    esac
    shift
  done
  if ! is_sha "$sha"; then
    echo "$prog: build needs a full lowercase 40-hex commit sha, got '$sha'" >&2
    exit 2
  fi
  case $scope in
    all | distro) ;;
    *)
      echo "$prog: --omit-scope '$scope': want all or distro" >&2
      exit 2
      ;;
  esac
  local trcmd=() gdcmd=()
  if [ -n "$runner" ]; then trcmd=("$runner"); else split_cmd trcmd "${TESTRUNNER:-go run ./tools/testrunner}"; fi
  if [ -n "$gdriver" ]; then gdcmd=("$gdriver"); else split_cmd gdcmd "${GATEDRIVER:-go run ./tools/gatedriver}"; fi
  setup
  set -e
  local sha10=${sha:0:10}

  # A published record is refused unless --force, before any slow step.
  local parent
  parent=$(record_tip "$sha")
  if [ -n "$parent" ] && [ "$force" != true ]; then
    die "refs/gate-records/$sha is already published ($parent); --force replaces it (the old record becomes the parent)"
  fi
  if [ -n "$parent" ]; then
    git fetch --quiet --no-tags "$remote" "+refs/gate-records/$sha:$ns/record" ||
      die "cannot fetch refs/gate-records/$sha from $remote"
    parent=$(git rev-parse "$ns/record^{commit}")
  fi

  # The shard reports (contract 9.2).
  git fetch --quiet --no-tags "$remote" "+refs/heads/claude/gate-results/$sha10/*:$ns/reports/*" ||
    die "cannot fetch the report branches claude/gate-results/$sha10/* from $remote"
  local refs=()
  mapfile -t refs < <(git for-each-ref --format='%(refname)' "$ns/reports/")
  [ ${#refs[@]} -gt 0 ] || die "no report branches claude/gate-results/$sha10/* on $remote; run the gate shards first (scripts/ci/gate-shard.sh)"

  # The candidate, checked out where its own tools run.
  if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
    git fetch --quiet --no-tags "$remote" "$sha" 2>/dev/null || true
  fi
  git cat-file -e "$sha^{commit}" 2>/dev/null || die "commit $sha is not in this clone and $remote would not serve it"
  wt="$tmp/candidate"
  git worktree add --quiet --detach "$wt" "$sha" || die "cannot check $sha out in a temporary worktree"

  mkdir -p "$tmp/x" "$tmp/reports"
  local ref branch leaf from adopted=()
  for ref in "${refs[@]}"; do
    branch="claude/gate-results/$sha10/${ref#"$ns/reports/"}"
    leaf=${ref##*/}
    [[ $leaf =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "report branch $branch: '$leaf' is not a report name"
    [ ! -e "$tmp/reports/$leaf" ] || die "two report branches end in '$leaf' (one is $branch)"
    if ! git cat-file -e "$ref:gate-results/$leaf/report.json" 2>/dev/null; then
      [ "$adopt" = true ] ||
        die "report branch $branch has no gate-results/$leaf/report.json; it is not a shard report of contract 9.2 (a branch of the layout before gate-shard.sh needs --adopt-legacy)"
      from=$(adopt_legacy "$ref" "$branch" "$leaf" "$sha" "$scope" "$tmp/reports/$leaf") || exit 3
      adopted+=("$(printf '# adopted\t%s\t%s\t%s' "$leaf" "$(git rev-parse "$ref^{commit}")" "$from")")
      note "adopted $branch ($from, $(jq -r '"shard \(.shard), \(.units) units, \(.verdict)"' "$tmp/reports/$leaf/report.json"))"
      continue
    fi
    git archive --format=tar "$ref" "gate-results/$leaf" | tar -x -C "$tmp/x" ||
      die "cannot extract gate-results/$leaf from $branch"
    mv "$tmp/x/gate-results/$leaf" "$tmp/reports/$leaf"
  done
  note "${#refs[@]} report branch(es) for $sha: $(cd "$tmp/reports" && printf '%s ' *)"

  local home
  home=$(mktemp -d "$tmp/trhome.XXXXXX")
  (cd "$wt" && "${trcmd[@]}" gate --full --omit-scope "$scope" --list-units --home "$home") >"$tmp/expected.txt" ||
    die "listing the units of $sha failed (${trcmd[*]} gate --list-units); a commit older than --list-units needs --runner <a testrunner built from a newer checkout>"
  local n
  n=$(grep -cv '^[[:space:]]*\(#.*\)\{0,1\}$' "$tmp/expected.txt" || true)
  [ "$n" -gt 0 ] || die "the unit listing of $sha is empty"
  note "$n unit(s) expected of $sha (--omit-scope $scope)"

  local hc="$wt/scripts/ci/gate-host-checks.tsv"
  if [ "$scope" = distro ]; then
    hc="$tmp/no-host-checks.tsv"
    : >"$hc"
    note "--omit-scope distro: a record of scope gate; no host check is expected"
  elif [ ! -f "$hc" ]; then
    die "$sha has no scripts/ci/gate-host-checks.tsv, so it cannot have a release record; build with --omit-scope distro"
  fi

  local host
  host=$(hostname 2>/dev/null || uname -n)
  (cd "$wt" && "${gdcmd[@]}" reports --sha "$sha" --expected "$tmp/expected.txt" --host-checks "$hc" \
    --reports "$tmp/reports" --out-dir "$tmp/out" --driver "$host $prog.sh build") >&2 ||
    die "gatedriver reports refused the reports of $sha (above); nothing published"
  local f
  for f in record.json ledger.snapshot.tsv reports.txt; do
    [ -f "$tmp/out/$f" ] || die "gatedriver reports wrote no $f"
  done
  [ "$(jq -r .sha "$tmp/out/record.json" 2>/dev/null)" = "$sha" ] || die "gatedriver reports wrote no record of $sha"
  if [ ${#adopted[@]} -gt 0 ]; then
    {
      printf '# adopted\treport\tbranch commit\tdirectory read (layout before gate-shard.sh; report.json derived by %s.sh build --adopt-legacy)\n' "$prog"
      printf '%s\n' "${adopted[@]}"
    } >>"$tmp/out/reports.txt"
  fi

  local commit
  commit=$(record_commit "$(git hash-object -w "$tmp/out/record.json")" \
    "$(git hash-object -w "$tmp/out/ledger.snapshot.tsv")" "$(git hash-object -w "$tmp/out/reports.txt")" \
    "gate record for $sha ($(jq -r '"scope \(.scope // "?"), \(.units_pass) units pass"' "$tmp/out/record.json"))" "$parent")
  local why
  why=$(record_verdict "$tmp/out/record.json" "$sha" '["release"]' "${GATE_RECORD_MIN_UNITS:-500}")
  if [ "$why" = ok ]; then
    note "check will answer gated=true: GitHub skips the covered jobs of $sha"
  else
    note "check will answer gated=false ($why); production accepts the record"
  fi
  if [ "$push" != true ]; then
    note "--no-push: the record commit is built, not published"
    echo "$commit"
    return 0
  fi
  push_record "$sha" "$commit"
  echo "$commit"
}

# ---------------------------------------------------------------- add-images

cmd_add_images() {
  local sha="" gdriver="" source="" specs=()
  while [ $# -gt 0 ]; do
    case $1 in
      --gatedriver | --source)
        [ $# -ge 2 ] || usage
        case $1 in --gatedriver) gdriver=$2 ;; --source) source=$2 ;; esac
        shift
        ;;
      --gatedriver=*) gdriver=${1#*=} ;;
      --source=*) source=${1#*=} ;;
      -*) usage ;;
      *)
        if [ -z "$sha" ]; then sha=$1; else specs+=("$1"); fi
        ;;
    esac
    shift
  done
  if ! is_sha "$sha"; then
    echo "$prog: add-images needs a full lowercase 40-hex commit sha, got '$sha'" >&2
    exit 2
  fi
  [ ${#specs[@]} -gt 0 ] || usage
  case $source in
    "" | ops-vm-build) ;;
    *)
      echo "$prog: --source '$source': the one build source is ops-vm-build" >&2
      exit 2
      ;;
  esac
  local s
  for s in "${specs[@]}"; do
    if [[ $s =~ ^[a-z0-9][a-z0-9._-]*=sha256:[0-9a-f]{64}@[^[:space:]]+$ ]]; then
      continue
    fi
    if [[ $s =~ ^[a-z0-9][a-z0-9._-]*=sha256:[0-9a-f]{64}$ ]]; then
      if [ -z "$source" ]; then
        echo "$prog: '$s' has no @<registry ref>: an image with no registry copy needs --source ops-vm-build" >&2
        exit 2
      fi
      continue
    fi
    echo "$prog: '$s' is not <name>=sha256:<64 hex image id>[@<registry ref>]" >&2
    exit 2
  done
  local gdcmd=()
  if [ -n "$gdriver" ]; then gdcmd=("$gdriver"); else split_cmd gdcmd "${GATEDRIVER:-go run ./tools/gatedriver}"; fi
  setup
  set -e

  local ref parent
  ref=$(fetch_record "$sha")
  parent=$(git rev-parse "$ref^{commit}")
  mkdir -p "$tmp/in" "$tmp/out"
  git show "$ref:record.json" >"$tmp/in/record.json" 2>/dev/null || die "the record of $sha ($parent) has no record.json"
  local led rep
  led=$(git rev-parse --verify --quiet "$ref:ledger.snapshot.tsv") || die "the record of $sha ($parent) has no ledger.snapshot.tsv"
  rep=$(git rev-parse --verify --quiet "$ref:reports.txt") || die "the record of $sha ($parent) has no reports.txt"
  [ "$(jq -r .sha "$tmp/in/record.json" 2>/dev/null)" = "$sha" ] || die "refs/gate-records/$sha does not hold a record of $sha"

  local args=()
  if [ -n "$source" ]; then args+=(--image-source "$source"); fi
  for s in "${specs[@]}"; do args+=(--image "$s"); done
  "${gdcmd[@]}" add-images --record "$tmp/in/record.json" --out "$tmp/out/record.json" "${args[@]}" >&2 ||
    die "gatedriver add-images refused (above); nothing published"
  [ -f "$tmp/out/record.json" ] || die "gatedriver add-images wrote no record"
  [ "$(jq -r .sha "$tmp/out/record.json" 2>/dev/null)" = "$sha" ] || die "gatedriver add-images wrote no record of $sha"
  if cmp -s "$tmp/in/record.json" "$tmp/out/record.json"; then
    note "the record of $sha already lists these images; nothing to publish"
    echo "$parent"
    return 0
  fi
  local names commit
  names=$(printf '%s\n' "${specs[@]}" | sed 's/=.*//' | paste -sd ' ' -)
  commit=$(record_commit "$(git hash-object -w "$tmp/out/record.json")" "$led" "$rep" \
    "gate record for $sha: images $names" "$parent")
  push_record "$sha" "$commit"
  echo "$commit"
}

# ---------------------------------------------------------------- show

cmd_show() {
  [ $# -eq 1 ] || usage
  if ! is_sha "$1"; then
    echo "$prog: show needs a full lowercase 40-hex commit sha, got '$1'" >&2
    exit 2
  fi
  setup
  set -e
  local ref
  ref=$(fetch_record "$1")
  git show "$ref:record.json" || die "the record of $1 has no record.json"
}

verb=${1:-}
if [ $# -gt 0 ]; then shift; fi
case $verb in
  check) cmd_check "$@" ;;
  build) cmd_build "$@" ;;
  add-images) cmd_add_images "$@" ;;
  show) cmd_show "$@" ;;
  *) usage ;;
esac
