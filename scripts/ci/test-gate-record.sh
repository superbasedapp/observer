#!/usr/bin/env bash
# test-gate-record.sh: hermetic test for scripts/ci/gate-record.sh (L-145).
#
# Builds a throwaway bare "origin" and a clone of it under a mktemp dir, with
# stub testrunner and gatedriver scripts standing in for `go run
# ./tools/testrunner` and `go run ./tools/gatedriver` (TESTRUNNER /
# GATEDRIVER), and runs every verb against them. No network, no Go, a private
# HOME and git config; nothing outside the temp dir is touched.
#
# Cases: build refuses without report branches; build --no-push (a
# parentless commit whose tree is exactly the three files, the candidate's
# worktree and fresh --home handed to the runner, the candidate's host-check
# table and every report handed to the verifier, nothing pushed, nothing
# left behind); build publishes; a published record is refused without
# --force and becomes the parent with it; --omit-scope distro (no host
# checks expected); --runner / --gatedriver over TESTRUNNER / GATEDRIVER; a
# failing runner, a failing verifier, a candidate without a host-check
# table, a report branch of another layout; --adopt-legacy (a branch of the
# layout before gate-shard.sh: the ledger copied unchanged, report.json
# derived from it, the adopted branches named in reports.txt; refused
# without the flag, with a name that says no shard, or with two result
# directories); bad arguments, and a runner with
# no git identity. check: true on a good record (a full clone, a shallow
# clone, $GITHUB_SHA) and false on every broken field (another commit, the
# verdict, the scope, version, mode, too few units, pass + env_known short of
# expected, no units expected, non-numeric units, malformed JSON, not an
# object, no record.json, no record, a bad sha, the floor, no jq), always
# exit 0, the answer also in $GITHUB_OUTPUT; --any-scope accepts scope gate.
# add-images: a child commit carrying the other two files unchanged, a
# repeat is a no-op, no record and a bad image spec are refused, an image
# with no registry copy needs --source ops-vm-build and is recorded with it,
# and a
# record that moved meanwhile is refused (non-fast-forward, never forced).
# show: the record, and a refusal without one.
#
# Usage: scripts/ci/test-gate-record.sh
#        GATE_RECORD_SCRIPT=/path/to/gate-record.sh scripts/ci/test-gate-record.sh
# Needs bash, git, jq and tar. Exit 0 = all cases pass.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${GATE_RECORD_SCRIPT:-${REPO_ROOT}/scripts/ci/gate-record.sh}"

for tool in git jq tar; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "SKIP: $tool is not installed"
    exit 0
  }
done

T="$(mktemp -d "${TMPDIR:-/tmp}/gate-record-test.XXXXXX")"
[[ -n "$T" && -d "$T" ]] || {
  echo "FAIL: mktemp"
  exit 1
}
trap 'rm -rf "$T"' EXIT

pass=0 fail=0
ok() {
  pass=$((pass + 1))
  echo "ok   $*"
}
bad() {
  fail=$((fail + 1))
  echo "FAIL $*"
}

# A private git: no user or system config, no hooks, a known identity.
unset GITHUB_OUTPUT GITHUB_SHA TESTRUNNER GATEDRIVER GATE_RECORD_MIN_UNITS GIT_DIR GIT_WORK_TREE \
  GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL STUB_TR_FAIL STUB_GD_FAIL STUB_RACE STUB_SCOPE
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$T/home/.gitconfig"
mkdir -p "$HOME"
# Outside every repository: this script's own checkout is not the fixture.
cd "$T" || exit 1
git config --global user.name "gate test"
git config --global user.email "gate-test@example.invalid"
git config --global init.defaultBranch main
git config --global advice.detachedHead false
git config --global protocol.file.allow always

# ---------------------------------------------------------------- stubs

mkdir -p "$T/bin" "$T/log"
export STUB_LOG="$T/log"

cat >"$T/bin/testrunner" <<'EOF'
#!/usr/bin/env bash
# stub testrunner: gate --full --omit-scope <s> --list-units --home <dir>
set -euo pipefail
echo "cwd=$(pwd) head=$(git rev-parse HEAD) args=$*" >>"$STUB_LOG/testrunner.log"
if [ "${STUB_TR_FAIL:-}" = 1 ]; then
  echo "flag provided but not defined: -list-units" >&2
  exit 2
fi
[ "$1 $2" = "gate --full" ] || { echo "stub testrunner: unexpected $*" >&2; exit 2; }
home=""
while [ $# -gt 0 ]; do
  case $1 in --home) home=$2; shift ;; esac
  shift
done
if [ ! -d "$home" ] || [ -n "$(ls -A "$home")" ]; then
  echo "stub testrunner: --home '$home' is not a fresh directory" >&2
  exit 2
fi
printf '# the units\ngo:internal/a\ngo:internal/b\n\nvet:no_obs\n'
EOF

cat >"$T/bin/gatedriver" <<'EOF'
#!/usr/bin/env bash
# stub gatedriver: reports and add-images, writing what the real verbs do.
set -euo pipefail
verb=$1
shift
echo "cwd=$(pwd) verb=$verb args=$*" >>"$STUB_LOG/gatedriver.log"
declare -A f=()
images=()
while [ $# -gt 0 ]; do
  case $1 in
    --image) images+=("$2") ;;
    --*) f[${1#--}]=$2 ;;
  esac
  shift 2
done
case $verb in
  reports)
    if [ "${STUB_GD_FAIL:-}" = 1 ]; then
      echo "reports.Verify: rule 4 (every unit's latest row in every report is pass or env_known): 1 unit row(s) not green" >&2
      exit 1
    fi
    for d in "${f[reports]}"/*/; do
      [ -f "$d/report.json" ] && [ -f "$d/ledger.tsv" ] || { echo "stub gatedriver: $d is not a report" >&2; exit 9; }
    done
    (cd "${f[reports]}" && ls | paste -sd, -) >"$STUB_LOG/reports.seen"
    rm -rf "$STUB_LOG/reports.copy"
    cp -r "${f[reports]}" "$STUB_LOG/reports.copy"
    cp "${f[host-checks]}" "$STUB_LOG/host-checks.seen"
    cp "${f[expected]}" "$STUB_LOG/expected.seen"
    printf '%s\n' "${f[driver]}" >"$STUB_LOG/driver.seen"
    mkdir -p "${f[out-dir]}"
    jq -n --arg sha "${f[sha]}" --arg driver "${f[driver]}" --arg scope "${STUB_SCOPE:-release}" '{
      version: 1, sha: $sha, mode: "full", verdict: "GATE PASS", gate_run: "tr-20261121-000000-abcdef",
      ledger_digest: "sha256:00", units_pass: 600, units_env_known: 2, driver: $driver,
      gated_at: "2026-11-21T00:00:00Z", images: null, scope: $scope, source: "shard-reports",
      units_expected: 602}' >"${f[out-dir]}/record.json"
    printf 'unit\tcommit\tresult\n' >"${f[out-dir]}/ledger.snapshot.tsv"
    paste -sd' ' "$STUB_LOG/reports.seen" >"${f[out-dir]}/reports.txt"
    ;;
  add-images)
    if [ "${STUB_RACE:-}" = 1 ]; then
      # Another writer publishes the record while this one works.
      sha=$(jq -r .sha "${f[record]}")
      c=$(git commit-tree "$(git mktree </dev/null)" -m "a concurrent writer")
      git push -q -f origin "$c:refs/gate-records/$sha"
      echo "$c" >"$STUB_LOG/race.commit"
    fi
    out=$(cat "${f[record]}")
    for s in "${images[@]}"; do
      name=${s%%=*} rest=${s#*=}
      if [[ $rest == *@* ]]; then
        out=$(jq --arg n "$name" --arg d "${rest%%@*}" --arg r "${rest#*@}" \
          '.images = (((.images // []) | map(select(.name != $n))) + [{name: $n, digest: $d, ref: $r}] | sort_by(.name))' <<<"$out")
      else
        out=$(jq --arg n "$name" --arg d "$rest" --arg s "${f[image-source]}" \
          '.images = (((.images // []) | map(select(.name != $n))) + [{name: $n, digest: $d, source: $s}] | sort_by(.name))' <<<"$out")
      fi
    done
    printf '%s\n' "$out" >"${f[out]}"
    ;;
  *)
    echo "stub gatedriver: unknown verb $verb" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$T/bin/testrunner" "$T/bin/gatedriver"
export TESTRUNNER="$T/bin/testrunner" GATEDRIVER="$T/bin/gatedriver"

# ---------------------------------------------------------------- fixture

ORIGIN="$T/origin.git"
git init -q --bare "$ORIGIN"
SEED="$T/seed"
git init -q "$SEED"
mkdir -p "$SEED/scripts/ci"
printf '# check\tcommand\ntrack-build\tmake verify-track-build\nhelm\tbash scripts/ci/helm.sh\n' >"$SEED/scripts/ci/gate-host-checks.tsv"
echo one >"$SEED/README"
git -C "$SEED" add -A
git -C "$SEED" commit -qm one
CAND=$(git -C "$SEED" rev-parse HEAD)
# CAND2 stands in for a commit older than the host-check table.
git -C "$SEED" rm -q scripts/ci/gate-host-checks.tsv
git -C "$SEED" commit -qm two
CAND2=$(git -C "$SEED" rev-parse HEAD)
git -C "$SEED" push -q "$ORIGIN" HEAD:refs/heads/main
CLONE="$T/clone"
git clone -q "$ORIGIN" "$CLONE"

push_report() { # push_report <sha> <name> [flat]: a report branch on origin
  local d="$T/rep-$1-$2"
  rm -rf "$d"
  git init -q "$d"
  if [ "${3:-}" = flat ]; then
    echo '{}' >"$d/report.json"
  else
    mkdir -p "$d/gate-results/$2"
    jq -n --arg sha "$1" '{version: 1, purpose: "sbo-gate-shard-report-v1", sha: $sha, shard: "1/2",
      scope: "release", omit_scope: "all", host_class: "cloud", verdict: "GATE PASS",
      runs: ["tr-1"], units: 1, host_checks: [], started_at: "2026-11-21T00:00:00Z",
      finished_at: "2026-11-21T00:10:00Z"}' >"$d/gate-results/$2/report.json"
    printf 'go:internal/a\t%s\tpass\t1\tcloud\t2026-11-21T00:00:00Z\ttr-1\tgo test\n' "$1" >"$d/gate-results/$2/ledger.tsv"
    echo "summary" >"$d/gate-results/$2/summary.md"
  fi
  git -C "$d" add -A
  git -C "$d" commit -qm "report $2"
  git -C "$d" push -q "$ORIGIN" "HEAD:refs/heads/claude/gate-results/${1:0:10}/$2"
}

# publish_raw <ref sha> <record.json text, or -none>: a hand-made record.
publish_raw() {
  local blobs="" b
  if [ "$2" != -none ]; then
    b=$(printf '%s\n' "$2" | git -C "$CLONE" hash-object -w --stdin)
    blobs+=$(printf '100644 blob %s\trecord.json' "$b")$'\n'
  fi
  b=$(printf 'unit\n' | git -C "$CLONE" hash-object -w --stdin)
  blobs+=$(printf '100644 blob %s\tledger.snapshot.tsv\n100644 blob %s\treports.txt' "$b" "$b")$'\n'
  local tree c
  tree=$(printf '%s' "$blobs" | git -C "$CLONE" mktree)
  c=$(git -C "$CLONE" commit-tree "$tree" -m raw)
  git -C "$CLONE" push -q -f origin "$c:refs/gate-records/$1"
}

fake() { printf '%040x' "$1"; }

good_json() { # good_json <sha> [jq filter applied to it]
  jq -cn --arg sha "$1" '{version: 1, sha: $sha, mode: "full", verdict: "GATE PASS", gate_run: "tr-1",
    ledger_digest: "sha256:00", units_pass: 600, units_env_known: 2, driver: "test",
    gated_at: "2026-11-21T00:00:00Z", scope: "release", source: "shard-reports",
    units_expected: 602}' | jq -c "${2:-.}"
}

rc=0
run() { # run <dir> <args...>: gate-record.sh in <dir>; out/err/rc
  local dir=$1
  shift
  (cd "$dir" && bash "$SCRIPT" "$@") >"$T/out" 2>"$T/err"
  rc=$?
}
has() { grep -qF -- "$1" "$T/out" "$T/err"; }
show_io() {
  echo "  rc=$rc"
  sed 's/^/  out: /' "$T/out"
  sed 's/^/  err: /' "$T/err"
}
remote_tip() { git -C "$ORIGIN" rev-parse -q --verify "refs/gate-records/$1" 2>/dev/null || true; }
tree_names() { git -C "$CLONE" ls-tree --name-only "$1" | paste -sd' ' -; }
parents() { git -C "$CLONE" log -1 --format=%P "$1"; }
log_lines() { if [ -f "$T/log/$1.log" ]; then wc -l <"$T/log/$1.log" | tr -d ' '; else echo 0; fi; }
clean_clone() { # no temporary refs or worktrees left behind
  [ -z "$(git -C "$CLONE" for-each-ref refs/gate-record-tmp)" ] &&
    [ "$(git -C "$CLONE" worktree list | wc -l | tr -d ' ')" = 1 ]
}
FILES="ledger.snapshot.tsv record.json reports.txt"

# ---------------------------------------------------------------- build

# 1. No report branch: refused, nothing published.
run "$CLONE" build "$CAND"
if [ $rc -eq 3 ] && has "no report branches claude/gate-results/${CAND:0:10}/*" && [ -z "$(remote_tip "$CAND")" ] && clean_clone; then
  ok "build refuses a commit with no report branch"
else
  bad "build without report branches"
  show_io
fi

push_report "$CAND" shard-1-of-2
push_report "$CAND" shard-2-of-2
push_report "$CAND" host-wsl

# 2. --no-push: the record commit is built, printed, not pushed.
run "$CLONE" build "$CAND" --no-push
C0=$(tr -d '\n' <"$T/out")
if [ $rc -eq 0 ] && [[ $C0 =~ ^[0-9a-f]{40}$ ]] && [ -z "$(remote_tip "$CAND")" ] && git -C "$CLONE" cat-file -e "$C0^{commit}" &&
  [ "$(tree_names "$C0")" = "$FILES" ] && [ -z "$(parents "$C0")" ] && clean_clone; then
  ok "build --no-push prints a parentless record commit of exactly the three files and pushes nothing"
else
  bad "build --no-push"
  show_io
fi
trl=$(tail -n1 "$T/log/testrunner.log")
if [[ $trl == *"head=$CAND "* ]] && [[ $trl == *"args=gate --full --omit-scope all --list-units --home "* ]] && [[ $trl != *"cwd=$CLONE "* ]]; then
  ok "build lists the units with the runner in a worktree of the candidate, fresh --home, --omit-scope all"
else bad "the runner call: $trl"; fi
gdl=$(tail -n1 "$T/log/gatedriver.log")
if [ "$(cat "$T/log/reports.seen")" = "host-wsl,shard-1-of-2,shard-2-of-2" ] && grep -q '^helm' "$T/log/host-checks.seen" &&
  grep -q '^go:internal/b$' "$T/log/expected.seen" && grep -q 'gate-record.sh build$' "$T/log/driver.seen" &&
  [[ $gdl == *"verb=reports args=--sha $CAND --expected "* ]] && [[ $gdl == *"/scripts/ci/gate-host-checks.tsv --reports "* ]]; then
  ok "build hands gatedriver reports every report, the listing and the candidate's host-check table"
else
  bad "the verifier call: $gdl"
  cat "$T/log/reports.seen" "$T/log/driver.seen"
fi

# 3. build publishes refs/gate-records/<sha>.
run "$CLONE" build "$CAND"
C1=$(tr -d '\n' <"$T/out")
if [ $rc -eq 0 ] && [ "$(remote_tip "$CAND")" = "$C1" ] && [ "$(tree_names "$C1")" = "$FILES" ] && [ -z "$(parents "$C1")" ] &&
  [ "$(git -C "$CLONE" show "$C1:record.json" | jq -r .sha)" = "$CAND" ] && has "gated=true" && clean_clone; then
  ok "build publishes a parentless record of the candidate"
else
  bad "build publish"
  show_io
fi

# 4. A published record is refused without --force, before any slow step.
n=$(log_lines testrunner)
run "$CLONE" build "$CAND"
if [ $rc -eq 3 ] && has "already published" && [ "$(remote_tip "$CAND")" = "$C1" ] && [ "$(log_lines testrunner)" = "$n" ]; then
  ok "build refuses to replace a published record without --force"
else
  bad "build over a published record"
  show_io
fi

# 5. --force: the old record becomes the parent.
run "$CLONE" build "$CAND" --force
C2=$(tr -d '\n' <"$T/out")
if [ $rc -eq 0 ] && [ "$(remote_tip "$CAND")" = "$C2" ] && [ "$(parents "$C2")" = "$C1" ] && [ "$C2" != "$C1" ]; then
  ok "build --force publishes a child of the old record"
else
  bad "build --force"
  show_io
fi

# 6. --omit-scope distro: the runner gets distro, no host check is expected.
STUB_SCOPE=gate run "$CLONE" build "$CAND" --no-push --force --omit-scope distro
if [ $rc -eq 0 ] && [[ $(tail -n1 "$T/log/testrunner.log") == *"--omit-scope distro --list-units"* ]] &&
  [ ! -s "$T/log/host-checks.seen" ] && has "gated=false" && [ "$(remote_tip "$CAND")" = "$C2" ]; then
  ok "build --omit-scope distro expects no host check (a scope gate record GitHub never skips on)"
else
  bad "build --omit-scope distro"
  show_io
fi

# 7. --runner / --gatedriver win over TESTRUNNER / GATEDRIVER.
TESTRUNNER=false GATEDRIVER=false run "$CLONE" build "$CAND" --no-push --force --runner "$T/bin/testrunner" --gatedriver "$T/bin/gatedriver"
if [ $rc -eq 0 ] && [[ $(tr -d '\n' <"$T/out") =~ ^[0-9a-f]{40}$ ]]; then
  ok "--runner and --gatedriver override TESTRUNNER and GATEDRIVER"
else
  bad "--runner / --gatedriver"
  show_io
fi
TESTRUNNER="$T/bin/testrunner extra" run "$CLONE" build "$CAND" --no-push --force
if [ $rc -eq 3 ] && [[ $(tail -n1 "$T/log/testrunner.log") == *"args=extra gate --full"* ]]; then
  ok "TESTRUNNER is a command line split on spaces"
else
  bad "TESTRUNNER word splitting"
  show_io
fi

# 8. A runner that cannot list units (an older commit): refused, names --runner.
STUB_TR_FAIL=1 run "$CLONE" build "$CAND" --force
if [ $rc -eq 3 ] && has "--runner" && [ "$(remote_tip "$CAND")" = "$C2" ] && clean_clone; then
  ok "a runner without --list-units is refused and the message names --runner"
else
  bad "failing runner"
  show_io
fi

# 9. The verifier refuses: nothing published.
STUB_GD_FAIL=1 run "$CLONE" build "$CAND" --force
if [ $rc -eq 3 ] && has "nothing published" && has "rule 4" && [ "$(remote_tip "$CAND")" = "$C2" ] && clean_clone; then
  ok "a refusal by gatedriver reports publishes nothing"
else
  bad "failing verifier"
  show_io
fi

# 10. A candidate without the host-check table: no release record; distro builds.
push_report "$CAND2" shard-1-of-1
run "$CLONE" build "$CAND2"
if [ $rc -eq 3 ] && has "gate-host-checks.tsv" && has "--omit-scope distro" && [ -z "$(remote_tip "$CAND2")" ]; then
  ok "a candidate without gate-host-checks.tsv gets no release record"
else
  bad "release build without a host-check table"
  show_io
fi
STUB_SCOPE=gate run "$CLONE" build "$CAND2" --omit-scope distro --no-push
if [ $rc -eq 0 ] && [ ! -s "$T/log/host-checks.seen" ]; then
  ok "the same candidate builds with --omit-scope distro"
else
  bad "distro build without a host-check table"
  show_io
fi

# 11. A report branch of another layout is refused by name.
push_report "$CAND2" old-shard flat
STUB_SCOPE=gate run "$CLONE" build "$CAND2" --omit-scope distro --no-push
if [ $rc -eq 3 ] && has "claude/gate-results/${CAND2:0:10}/old-shard" && has "gate-results/old-shard/report.json" && clean_clone; then
  ok "a report branch without gate-results/<name>/report.json is refused, naming the branch"
else
  bad "report branch of another layout"
  show_io
fi

# 11b. --adopt-legacy: report branches of the layout before gate-shard.sh.
git -C "$SEED" commit -q --allow-empty -m three
CAND3=$(git -C "$SEED" rev-parse HEAD)
git -C "$SEED" push -q "$ORIGIN" HEAD:refs/heads/three
git -C "$CLONE" fetch -q origin three
push_legacy() { # push_legacy <sha> <branch name> <dir> <ledger file> [env text] [summary text]
  local d="$T/leg-$1-$2"
  rm -rf "$d"
  git init -q "$d"
  mkdir -p "$d/gate-results/$3"
  cp "$4" "$d/gate-results/$3/ledger.tsv"
  if [ -n "${5:-}" ]; then printf '%s\n' "$5" >"$d/gate-results/$3/env.txt"; fi
  printf '%s\n' "${6:-summary}" >"$d/gate-results/$3/summary.md"
  echo log >"$d/gate-results/$3/gate.log"
  git -C "$d" add -A
  git -C "$d" commit -qm "legacy $2"
  git -C "$d" push -q -f "$ORIGIN" "HEAD:refs/heads/claude/gate-results/${1:0:10}/$2"
  git -C "$d" rev-parse HEAD
}
hdr=$'# unit\tcommit\tresult\tduration_s\tprovider\ttime\trun\tcmd'
{
  echo "$hdr"
  printf 'go:internal/a\t%s\tnot_run\t0.0\t\t2026-11-21T00:00:00Z\ttr-0\tgate\n' "$CAND3"
  printf 'go:internal/a\t%s\tpass\t1.0\tlocal\t2026-11-21T00:05:00Z\ttr-1\tgate\n' "$CAND3"
  printf 'go:internal/b\t%s\tfail\t2.0\tlocal\t2026-11-21T00:10:00Z\ttr-1\tgate\n' "$CAND3"
} >"$T/leg1.tsv"
{
  echo "$hdr"
  printf 'vet:no_obs\t%s\tpass\t3.0\tlocal\t2026-11-21T00:07:00Z\ttr-2\tgate\n' "$CAND3"
} >"$T/leg2.tsv"
{
  echo "$hdr"
  printf 'go:internal/b\t%s\tpass\t2.5\tlocal\t2026-11-21T01:00:00Z\ttr-3\trun\n' "$CAND3"
} >"$T/legr.tsv"
L1=$(push_legacy "$CAND3" shard-1-of-2 shard-1 "$T/leg1.tsv" "Linux vm 6.18.44-fc-v726 x86_64")
push_legacy "$CAND3" shard-2-of-2 shard-2 "$T/leg2.tsv" "Linux box 6.6.87.2-microsoft-standard-WSL2" >/dev/null
LR=$(push_legacy "$CAND3" rerun-b rerun-b "$T/legr.tsv" "" "Rerun on the operator's WSL box")

STUB_SCOPE=gate run "$CLONE" build "$CAND3" --omit-scope distro --no-push
if [ $rc -eq 3 ] && has "claude/gate-results/${CAND3:0:10}/" && has "--adopt-legacy" && clean_clone; then
  ok "a branch of the layout before gate-shard.sh is refused without --adopt-legacy, naming the flag"
else
  bad "legacy branch without --adopt-legacy"
  show_io
fi

STUB_SCOPE=gate run "$CLONE" build "$CAND3" --omit-scope distro --no-push --adopt-legacy
C4=$(tr -d '\n' <"$T/out")
rc4=$rc
rj() { jq -c "$2" "$T/log/reports.copy/$1/report.json"; }
if [ $rc4 -eq 0 ] && [[ $C4 =~ ^[0-9a-f]{40}$ ]] && [ "$(cat "$T/log/reports.seen")" = "rerun-b,shard-1-of-2,shard-2-of-2" ] &&
  [ -z "$(remote_tip "$CAND3")" ] && clean_clone; then
  ok "build --adopt-legacy hands the verifier one report per legacy branch, the rerun included"
else
  bad "build --adopt-legacy"
  show_io
fi
if [ "$(rj shard-1-of-2 '[.version, .purpose, .sha, .shard, .scope, .omit_scope, .host_class, .verdict, .runs, .units, .host_checks, .started_at, .finished_at]')" = \
  "[1,\"sbo-gate-shard-report-v1\",\"$CAND3\",\"1/2\",\"gate\",\"distro\",\"cloud\",\"GATE FAIL\",[\"tr-0\",\"tr-1\"],2,[],\"2026-11-21T00:00:00Z\",\"2026-11-21T00:10:00Z\"]" ] &&
  [ "$(rj shard-2-of-2 '[.shard, .host_class, .verdict, .units]')" = '["2/2","wsl","GATE PASS",1]' ] &&
  [ "$(rj rerun-b '[.shard, .host_class, .verdict, .runs]')" = '["rerun","wsl","GATE PASS",["tr-3"]]' ]; then
  ok "the derived report.json: shard from the name, scope from --omit-scope, verdict from the ledger, host class from env.txt or the summary"
else
  bad "derived report.json"
  for n in shard-1-of-2 shard-2-of-2 rerun-b; do jq -c . "$T/log/reports.copy/$n/report.json" 2>&1 | sed 's/^/  /'; done
fi
if cmp -s "$T/leg1.tsv" "$T/log/reports.copy/shard-1-of-2/ledger.tsv" && cmp -s "$T/legr.tsv" "$T/log/reports.copy/rerun-b/ledger.tsv" &&
  [ -f "$T/log/reports.copy/shard-1-of-2/env.txt" ] && [ -f "$T/log/reports.copy/rerun-b/summary.md" ] &&
  [ ! -e "$T/log/reports.copy/shard-1-of-2/gate.log" ]; then
  ok "an adopted ledger is copied byte for byte, with summary.md and env.txt beside it"
else
  bad "adopted ledger copy"
fi
if [ $rc4 -eq 0 ] && git -C "$CLONE" show "$C4:reports.txt" | grep -qF "$(printf '# adopted\tshard-1-of-2\t%s\tgate-results/shard-1' "$L1")" &&
  git -C "$CLONE" show "$C4:reports.txt" | grep -qF "$(printf '# adopted\trerun-b\t%s\tgate-results/rerun-b' "$LR")"; then
  ok "reports.txt names each adopted branch, its commit and the directory read"
else
  bad "adopted lines in reports.txt"
  git -C "$CLONE" show "$C4:reports.txt" 2>&1 | sed 's/^/  /'
fi

push_legacy "$CAND3" old-name old "$T/leg2.tsv" >/dev/null
STUB_SCOPE=gate run "$CLONE" build "$CAND3" --omit-scope distro --no-push --adopt-legacy
if [ $rc -eq 3 ] && has "'old-name' is neither shard-<i>-of-<n> nor rerun-<name>" && clean_clone; then
  ok "--adopt-legacy refuses a branch whose name says no shard"
else
  bad "--adopt-legacy with a bad name"
  show_io
fi
git -C "$ORIGIN" update-ref -d "refs/heads/claude/gate-results/${CAND3:0:10}/old-name"
d2="$T/leg-two"
rm -rf "$d2"
git init -q "$d2"
mkdir -p "$d2/gate-results/a" "$d2/gate-results/b"
cp "$T/leg2.tsv" "$d2/gate-results/a/ledger.tsv"
cp "$T/leg2.tsv" "$d2/gate-results/b/ledger.tsv"
git -C "$d2" add -A
git -C "$d2" commit -qm two
git -C "$d2" push -q "$ORIGIN" "HEAD:refs/heads/claude/gate-results/${CAND3:0:10}/rerun-two"
STUB_SCOPE=gate run "$CLONE" build "$CAND3" --omit-scope distro --no-push --adopt-legacy
if [ $rc -eq 3 ] && has "exactly one directory under gate-results/, found 2" && clean_clone; then
  ok "--adopt-legacy refuses a branch with two result directories"
else
  bad "--adopt-legacy with two directories"
  show_io
fi
git -C "$ORIGIN" update-ref -d "refs/heads/claude/gate-results/${CAND3:0:10}/rerun-two"

# 12. Bad arguments are usage errors.
run "$CLONE" build "${CAND:0:12}"
r1=$rc
run "$CLONE" build "$CAND" --omit-scope narrow
r2=$rc
run "$CLONE" build "$CAND" --bogus
r3=$rc
run "$CLONE" frobnicate
r4=$rc
if [ "$r1 $r2 $r3 $r4" = "2 2 2 2" ]; then ok "a short sha, an unknown omit scope, an unknown flag and an unknown verb exit 2"; else bad "usage exits: $r1 $r2 $r3 $r4"; fi

# 13. A runner with no git identity (GitHub's) still commits.
printf '[user]\n\tuseConfigOnly = true\n' >"$T/noident.gitconfig"
GIT_CONFIG_GLOBAL="$T/noident.gitconfig" run "$CLONE" build "$CAND" --no-push --force
C3=$(tr -d '\n' <"$T/out")
if [ $rc -eq 0 ] && [ "$(git -C "$CLONE" log -1 --format='%an <%ae>' "$C3")" = "gate-record <gate-record@localhost>" ]; then
  ok "build commits under a fallback identity when git has none"
else
  bad "build with no git identity"
  show_io
fi

# ---------------------------------------------------------------- check

why=""
expect_check() { # expect_check <true|false> <name> <dir> <args...>; $why: the stderr reason
  local want=$1 name=$2 dir=$3
  shift 3
  : >"$T/gh_output"
  (cd "$dir" && GITHUB_OUTPUT="$T/gh_output" bash "$SCRIPT" check "$@") >"$T/out" 2>"$T/err"
  rc=$?
  if [ $rc -eq 0 ] && [ "$(cat "$T/out")" = "gated=$want" ] && [ "$(cat "$T/gh_output")" = "gated=$want" ] &&
    [ -s "$T/err" ] && grep -qF -- "${why:-gate-record: }" "$T/err"; then
    ok "check: $name -> gated=$want"
  else
    bad "check: $name (want gated=$want)"
    show_io
  fi
}

why="a full gate passed $CAND (scope release, 600 pass + 2 env_known of 602 expected units"
expect_check true "the published release record" "$CLONE" "$CAND"
git clone -q --depth=1 "file://$ORIGIN" "$T/shallow"
expect_check true "the same record from a shallow clone" "$T/shallow" "$CAND"
(cd "$CLONE" && GITHUB_SHA="$CAND" bash "$SCRIPT" check) >"$T/out" 2>"$T/err"
if [ "$(cat "$T/out")" = "gated=true" ]; then ok "check: the sha defaults to \$GITHUB_SHA"; else bad "check with \$GITHUB_SHA"; fi
if [ ! -e "$CLONE/.git/shallow" ]; then ok "check leaves a full clone unshallow"; else bad "check made the full clone shallow"; fi

i=100
case_record() { # case_record <want> <name> <jq filter on a good record> <stderr reason> [check flags]
  i=$((i + 1))
  local s
  s=$(fake "$i")
  publish_raw "$s" "$(good_json "$s" "$3")"
  why=$4 expect_check "$1" "$2" "$CLONE" "$s" "${@:5}"
}
case_record true "a well-formed record (the fixture itself)" '.' "a full gate passed"
case_record false "a record of another commit" ".sha = \"$(fake 999)\"" "it is the record of \"$(fake 999)\""
case_record false "verdict GATE FAIL" '.verdict = "GATE FAIL"' 'verdict "GATE FAIL", want "GATE PASS"'
case_record false "scope gate" '.scope = "gate"' 'scope "gate", want release;'
case_record true "scope gate with --any-scope" '.scope = "gate"' "(scope gate," --any-scope
case_record false "no scope" 'del(.scope)' "scope null, want release;"
case_record false "no scope with --any-scope" 'del(.scope)' "scope null, want release or gate" --any-scope
case_record false "version 2" '.version = 2' "version 2, want 1"
case_record false "mode affected" '.mode = "affected"' 'mode "affected", want "full"'
case_record false "499 passing units" '.units_pass = 499 | .units_expected = 400' "499 passing units, fewer than 500"
case_record false "pass + env_known short of expected" '.units_env_known = 1' "600 pass + 1 env_known cover fewer than the 602 expected"
case_record true "no env_known, pass covers expected" 'del(.units_env_known) | .units_expected = 600' "600 pass + 0 env_known of 600"
case_record false "no units expected" '.units_expected = 0' "units_expected 0, want more than 0"
case_record false "units_expected missing" 'del(.units_expected)' "is not a number"
case_record false "units_pass a string" '.units_pass = "600"' "is not a number"
case_record false "a failing gate with --any-scope" '.verdict = "GATE FAIL"' 'verdict "GATE FAIL"' --any-scope

i=$((i + 1))
s=$(fake "$i")
publish_raw "$s" '{"version": 1, "sha": '
why="record.json is not valid JSON" expect_check false "malformed JSON" "$CLONE" "$s"
i=$((i + 1))
s=$(fake "$i")
publish_raw "$s" '[1, 2]'
why="not a JSON object" expect_check false "a JSON array" "$CLONE" "$s"
i=$((i + 1))
s=$(fake "$i")
publish_raw "$s" -none
why="has no record.json" expect_check false "a record commit without record.json" "$CLONE" "$s"
why="no gate record for $(fake 50)" expect_check false "no record" "$CLONE" "$(fake 50)"
why="no full commit sha" expect_check false "a short sha" "$CLONE" "${CAND:0:10}"
why="no full commit sha" expect_check false "no sha and no \$GITHUB_SHA" "$CLONE"
why="unexpected argument" expect_check false "two shas" "$CLONE" "$CAND" "$CAND"
GATE_RECORD_MIN_UNITS=1000 why="600 passing units, fewer than 1000" expect_check false "a floor above the passing units" "$CLONE" "$CAND"
GATE_RECORD_MIN_UNITS=abc why="is not a number" expect_check false "a floor that is not a number" "$CLONE" "$CAND"
why=""
mkdir -p "$T/nojq"
ln -s "$(command -v git)" "$T/nojq/git"
(cd "$CLONE" && PATH="$T/nojq" "$BASH" "$SCRIPT" check "$CAND") >"$T/out" 2>"$T/err"
rc=$?
if [ $rc -eq 0 ] && [ "$(cat "$T/out")" = "gated=false" ] && has "jq missing"; then ok "check: no jq -> gated=false"; else
  bad "check without jq"
  show_io
fi

# ---------------------------------------------------------------- add-images

IMG_ORG="observer-org=sha256:$(printf 'a%.0s' {1..64})@reg.example/observer-org@sha256:$(printf 'b%.0s' {1..64})"
IMG_CLOUD="observer-cloud=sha256:$(printf 'c%.0s' {1..64})@reg.example/observer-cloud@sha256:$(printf 'd%.0s' {1..64})"
IMG_HARNESS="harness-gateway=sha256:$(printf 'e%.0s' {1..64})@reg.example/harness-gateway@sha256:$(printf 'f%.0s' {1..64})"

before=$(remote_tip "$CAND")
run "$CLONE" add-images "$CAND" "$IMG_ORG" "$IMG_CLOUD"
A1=$(remote_tip "$CAND")
if [ $rc -eq 0 ] && [ "$(tr -d '\n' <"$T/out")" = "$A1" ] && [ "$(parents "$A1")" = "$before" ] && [ "$(tree_names "$A1")" = "$FILES" ] &&
  [ "$(git -C "$CLONE" rev-parse "$A1:ledger.snapshot.tsv")" = "$(git -C "$CLONE" rev-parse "$before:ledger.snapshot.tsv")" ] &&
  [ "$(git -C "$CLONE" rev-parse "$A1:reports.txt")" = "$(git -C "$CLONE" rev-parse "$before:reports.txt")" ] &&
  [ "$(git -C "$CLONE" show "$A1:record.json" | jq -r '[.images[].name] | join(",")')" = "observer-cloud,observer-org" ] &&
  [[ $(tail -n1 "$T/log/gatedriver.log") == *"verb=add-images args=--record "*"--image $IMG_ORG --image $IMG_CLOUD"* ]] && clean_clone; then
  ok "add-images publishes a child commit with the images, the other two files unchanged"
else
  bad "add-images"
  show_io
fi
expect_check true "the record after add-images" "$CLONE" "$CAND"

run "$CLONE" add-images "$CAND" "$IMG_ORG"
if [ $rc -eq 0 ] && has "already lists" && [ "$(remote_tip "$CAND")" = "$A1" ]; then
  ok "add-images of images the record already lists publishes nothing"
else
  bad "add-images repeat"
  show_io
fi

run "$CLONE" add-images "$(fake 60)" "$IMG_ORG"
if [ $rc -eq 3 ] && has "no gate record" && [ -z "$(remote_tip "$(fake 60)")" ]; then ok "add-images refuses a commit with no record"; else
  bad "add-images without a record"
  show_io
fi

run "$CLONE" add-images "$CAND" "observer-org=latest@reg.example/observer-org:v1"
r1=$rc
run "$CLONE" add-images "$CAND"
r2=$rc
if [ "$r1 $r2" = "2 2" ] && [ "$(remote_tip "$CAND")" = "$A1" ]; then ok "add-images refuses a bad image spec and no image"; else bad "add-images usage: $r1 $r2"; fi

# An image with no registry copy: <name>=<id> needs --source ops-vm-build.
IMG_BUILT="observer-edge=sha256:$(printf '9%.0s' {1..64})"
run "$CLONE" add-images "$CAND" "$IMG_BUILT"
r1=$rc
run "$CLONE" add-images "$CAND" --source laptop "$IMG_BUILT"
r2=$rc
if [ "$r1 $r2" = "2 2" ] && grep -qF -- "--source" "$T/err" && [ "$(remote_tip "$CAND")" = "$A1" ]; then
  ok "add-images refuses an image with no @<ref> without --source ops-vm-build, and any other source"
else bad "add-images without a source: $r1 $r2"; fi
run "$CLONE" add-images "$CAND" --source ops-vm-build "$IMG_BUILT"
A2=$(remote_tip "$CAND")
if [ $rc -eq 0 ] && [ "$(parents "$A2")" = "$A1" ] &&
  [ "$(git -C "$CLONE" show "$A2:record.json" | jq -c '.images[] | select(.name == "observer-edge") | [.source, (.ref // "none")]')" = '["ops-vm-build","none"]' ] &&
  [[ $(tail -n1 "$T/log/gatedriver.log") == *"verb=add-images args=--record "*"--image-source ops-vm-build --image $IMG_BUILT"* ]] && clean_clone; then
  ok "add-images --source ops-vm-build records the image with its source and no reference"
else
  bad "add-images --source ops-vm-build"
  show_io
fi

# ---------------------------------------------------------------- show

run "$CLONE" show "$CAND"
if [ $rc -eq 0 ] && [ "$(jq -r .sha "$T/out")" = "$CAND" ] && [ "$(jq '.images | length' "$T/out")" = 3 ]; then ok "show prints the published record"; else
  bad "show"
  show_io
fi
run "$CLONE" show "$(fake 61)"
if [ $rc -eq 3 ] && has "no gate record"; then ok "show refuses a commit with no record"; else
  bad "show without a record"
  show_io
fi

# ---------------------------------------------------------------- the race

# Last: it leaves the stub's record on origin.
STUB_RACE=1 run "$CLONE" add-images "$CAND" "$IMG_HARNESS"
if [ $rc -eq 3 ] && has "refused" && [ "$(remote_tip "$CAND")" = "$(cat "$T/log/race.commit")" ] && clean_clone; then
  ok "add-images refuses a non-fast-forward when the record moved meanwhile (never forced)"
else
  bad "add-images race"
  show_io
fi

echo "gate-record.sh: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
