#!/usr/bin/env bash
# org-postgres-suite.sh - run the org-server test suites that are gated on a
# live PostgreSQL DSN, against a real Postgres, and FAIL if any of those
# live-PG tests silently skipped.
#
# Background: since D-24 dbtest.New opens PostgreSQL by default, and every
# dbtest PostgreSQL fixture (New, NewPostgres, NewPostgresDSN, the "postgres"
# case of ForEachEngine) FAILS its test when OBSERVER_CONTROL_STORE_DSN is
# unset. controltest's "postgres" dialect and the TestLivePG* tests of
# controlstore / leader / pgmigrations still t.Skip() without it. So a plain
# `go test` (no DSN) fails every package that opens a PostgreSQL fixture, and
# the two-writer / MVCC-guard proofs (plan acceptance criterion 9) and the
# both-dialects-green proofs (criterion 7) that only skip contribute ZERO
# coverage. This script is the CI wrapper that (a) points every DSN env var
# the test helpers read at a real Postgres and (b) turns a live-PG skip into
# a job failure, because in this job a skipped live-PG test is exactly the
# regression we are guarding against.
#
# The caller (the workflow) is responsible for providing a reachable Postgres
# and exporting OBSERVER_CONTROL_STORE_DSN / OBSERVER_DATA_STORE_DSN. This
# script fails closed if the control DSN is missing.
#
# Env the org-server test helpers read (grepped from
# internal/orgserver/db/dbtest, internal/orgserver/controlstore,
# internal/orgserver/leader and the pgmigrations tests):
#   OBSERVER_CONTROL_STORE_DSN   primary DSN; unset => every dbtest PostgreSQL
#                                fixture fails and every other live-PG test skips
#   OBSERVER_POSTGRES_URL        alternate name controlstore/leader/controltest accept
#   OBSERVER_DATA_STORE_DSN      data-plane DSN (role=all points it at the same db)
#   OBSERVER_CONTROL_STORE_LIVE  set to 1 by the live_pg / controltest helpers themselves
#   OBSERVER_DBTEST_ENGINE       engine dbtest.New opens: unset (or postgres) is
#                                PostgreSQL, the default since D-24, which is what
#                                this suite runs; sqlite is the deprecated opt-in
#                                that makes New open SQLite and the PostgreSQL
#                                fixtures skip. We DO NOT set it. ForEachEngine
#                                runs its sqlite and postgres cases either way.
#   OBSERVER_DBTEST_USE_TEMPLATE clones one migrated template per server and
#                                lineage version for every PostgreSQL fixture
#                                (unset is 1, the default; 0 migrates each one)
#   OBSERVER_DBTEST_BASE_TEMPLATE optional pre-migrated base (unused here)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [[ -z "${OBSERVER_CONTROL_STORE_DSN:-}" ]]; then
  echo "org-postgres-suite: OBSERVER_CONTROL_STORE_DSN is empty." >&2
  echo "org-postgres-suite: refusing to run - without a live DSN every dbtest PostgreSQL fixture fails" >&2
  echo "org-postgres-suite: and every other live-PG test skips, the silent-skip gap this job exists to close." >&2
  exit 1
fi
# role=all points the data plane at the same database as control.
export OBSERVER_DATA_STORE_DSN="${OBSERVER_DATA_STORE_DSN:-${OBSERVER_CONTROL_STORE_DSN}}"
# Speed the ForEachEngine disposable-database fixtures: clone a migrated
# template rather than re-running the whole lineage per test. The CI service
# container is ephemeral, so leaked templates are cleaned up with it.
export OBSERVER_DBTEST_USE_TEMPLATE="${OBSERVER_DBTEST_USE_TEMPLATE:-1}"

log="${ORG_PG_SUITE_LOG:-$(mktemp -t org-pg-suite.XXXXXX.log)}"

# --------------------------------------------------------------------------
# The package list and the live-PG marker live in ONE place,
# scripts/ci/org-postgres-suite.tsv, which tools/testrunner reads too (its
# @pg units). The list is derived at CI time so it never goes stale: the
# union over the derive rows of every package under a row's roots declaring
# a test line that matches the row's regexp (the two-writer / concurrency
# suites, plan acceptance criterion 9, and every package whose tests open a
# PostgreSQL fixture, D-24), plus the fixed packages the file lists with their
# reasons (the migration lineages and dbtest, the leader, the control-store
# dialect suite, ingest, the org CLI, and the ForEachEngine packages with no
# TwoWriters test, D-712 and T-861).
# --------------------------------------------------------------------------
suite_file="scripts/ci/org-postgres-suite.tsv"
derive_res=() derive_roots=() live_re="" fixed_pkgs=()
while IFS=$'\t' read -r kind a b; do
  case "${kind}" in
    ""|"#"*) continue ;;
    derive) derive_res+=("${a}"); derive_roots+=("${b}") ;;
    package) fixed_pkgs+=("${a}") ;;
    live) live_re="${a}" ;;
    *) echo "org-postgres-suite: unknown row kind '${kind}' in ${suite_file}" >&2; exit 1 ;;
  esac
done <"${suite_file}"
if [[ "${#derive_res[@]}" -eq 0 || -z "${live_re}" || "${#fixed_pkgs[@]}" -eq 0 ]]; then
  echo "org-postgres-suite: ${suite_file} lacks a derive, live or package row" >&2
  exit 1
fi
derived_pkgs=()
for i in "${!derive_res[@]}"; do
  if [[ -z "${derive_roots[$i]// /}" ]]; then
    echo "org-postgres-suite: derive row '${derive_res[$i]}' in ${suite_file} names no root" >&2
    exit 1
  fi
  # shellcheck disable=SC2086 # the roots are a space separated list on purpose
  mapfile -t row_pkgs < <(
    grep -rl "${derive_res[$i]}" --include='*_test.go' ${derive_roots[$i]} \
      | xargs -r -n1 dirname \
      | sort -u \
      | sed 's#^#./#'
  )
  if [[ "${#row_pkgs[@]}" -eq 0 ]]; then
    echo "org-postgres-suite: derive row '${derive_res[$i]}' derived ZERO packages - the grep pattern drifted." >&2
    echo "org-postgres-suite: this must not happen; failing so the miss is loud." >&2
    exit 1
  fi
  echo "org-postgres-suite: derive '${derive_res[$i]}': ${#row_pkgs[@]} package(s)"
  derived_pkgs+=("${row_pkgs[@]}")
done
mapfile -t derived_pkgs < <(printf '%s\n' "${derived_pkgs[@]}" | sort -u)
mapfile -t packages < <(printf '%s\n' "${derived_pkgs[@]}" "${fixed_pkgs[@]}" | sort -u)

echo "org-postgres-suite: ${#derived_pkgs[@]} derived package(s) + ${#fixed_pkgs[@]} fixed package glob(s):"
printf '  %s\n' "${packages[@]}"
echo "org-postgres-suite: log -> ${log}"

# -p 1 serializes the per-package test binaries. Every dbtest and controltest
# fixture gets a database of its own (dbtest.NewPostgres creates and drops
# one per call, cloned from a template built under an advisory lock; T-316
# moved controltest onto it, and controltest's TestNoTestOpensTheShadowSchemaPool
# keeps every package but controlstore off controlstore.OpenLive, the one
# helper that applies DDL to the DSN's own database). So the fixtures no
# longer need -p 1. But about 50 test files still read the DSN directly
# (cmd/observer-org, internal/mcpgw, tests/e2e, pgmigrations, ...); the ones
# sampled take a fixture database or a uniquely named schema, but they have
# not all been audited for the DSN's own database, so -p 1 stays until they
# are (dropping it is then a free speedup). Parallelism WITHIN a package is
# unaffected. -count=1 defeats the test
# cache. -timeout 90m is the per-binary timeout go-test-run.sh uses: the
# suite now holds the large org packages (internal/orgserver, cmd/observer-org),
# which outrun go test's 10m default. CGO stays disabled per the repo standard
# (modernc.org/sqlite is pure Go).
test_status=0
CGO_ENABLED="${CGO_ENABLED:-0}" go test -p 1 -count=1 -timeout 90m -v "${packages[@]}" 2>&1 | tee "${log}" || test_status="${PIPESTATUS[0]}"

# --------------------------------------------------------------------------
# FAIL-IF-SKIPPED guard. In this job a live-PG test that skipped means the DSN
# did not reach it (a wiring regression) - a silent skip is worse than a
# failure because it looks green. Count SKIP lines whose test name matches
# the live-PG marker (the live row of org-postgres-suite.tsv):
#   /postgres   - the ForEachEngine + controltest.Dialects "postgres" subtest
#   LivePG      - TestLivePG* (controlstore, leader, pgmigrations baseline/apply)
#   TwoWriters  - the concurrency suites (belt-and-braces; their PG halves are
#                 also caught by /postgres)
# tools/testrunner applies the same marker to the go test -json stream of
# its @pg units (workerexec exitRules).
# --------------------------------------------------------------------------
skipped_live_pg="$(grep -E '^[[:space:]]*--- SKIP' "${log}" | grep -E "${live_re}" || true)"
skip_count=0
if [[ -n "${skipped_live_pg}" ]]; then
  skip_count="$(printf '%s\n' "${skipped_live_pg}" | grep -c . || true)"
fi

ran_live_pg="$(grep -Ec "^[[:space:]]*--- (PASS|FAIL): .*(${live_re})" "${log}" || true)"
echo "org-postgres-suite: live-PG tests that ran (PASS+FAIL): ${ran_live_pg}"
echo "org-postgres-suite: live-PG tests that SKIPPED:        ${skip_count}"

if [[ "${skip_count}" -ne 0 ]]; then
  echo "::error::org-postgres-suite: ${skip_count} live-PG test(s) SKIPPED - the DSN did not reach them. A live-PG skip in this job is a failure." >&2
  printf '%s\n' "${skipped_live_pg}" >&2
  exit 1
fi

if [[ "${ran_live_pg}" -eq 0 ]]; then
  echo "::error::org-postgres-suite: ZERO live-PG tests ran. Either the DSN is not wired or the suite selection broke." >&2
  exit 1
fi

if [[ "${test_status}" -ne 0 ]]; then
  echo "::error::org-postgres-suite: go test failed (exit ${test_status})." >&2
  exit "${test_status}"
fi

echo "org-postgres-suite: PASS - ${ran_live_pg} live-PG tests ran, 0 skipped."
