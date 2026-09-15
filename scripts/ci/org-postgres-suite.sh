#!/usr/bin/env bash
# org-postgres-suite.sh - run the org-server test suites that are gated on a
# live PostgreSQL DSN, against a real Postgres, and FAIL if any of those
# live-PG tests silently skipped.
#
# Background: dbtest.ForEachEngine and controltest.Dialects each run a
# "postgres" subtest that t.Skip()s when OBSERVER_CONTROL_STORE_DSN is unset,
# and controlstore/leader/pgmigrations carry TestLivePG* tests with the same
# skip. On a plain `go test` (no DSN) every one of those skips, so the two-
# writer / MVCC-guard proofs (plan acceptance criterion 9) and the both-
# dialects-green proofs (criterion 7) contribute ZERO coverage. This script is
# the CI wrapper that (a) points every DSN env var the test helpers read at a
# real Postgres and (b) turns a live-PG skip into a job failure, because in
# this job a skipped live-PG test is exactly the regression we are guarding
# against.
#
# The caller (the workflow) is responsible for providing a reachable Postgres
# and exporting OBSERVER_CONTROL_STORE_DSN / OBSERVER_DATA_STORE_DSN. This
# script fails closed if the control DSN is missing.
#
# Env the org-server test helpers read (grepped from
# internal/orgserver/db/dbtest, internal/orgserver/controlstore,
# internal/orgserver/leader and the pgmigrations tests):
#   OBSERVER_CONTROL_STORE_DSN   primary DSN; unset => every live-PG test skips
#   OBSERVER_POSTGRES_URL        alternate name controlstore/leader/controltest accept
#   OBSERVER_DATA_STORE_DSN      data-plane DSN (role=all points it at the same db)
#   OBSERVER_CONTROL_STORE_LIVE  set to 1 by the live_pg / controltest helpers themselves
#   OBSERVER_DBTEST_ENGINE       suite selector for dbtest.New (we DO NOT set it: we
#                                want ForEachEngine to run BOTH engines, not force one)
#   OBSERVER_DBTEST_USE_TEMPLATE clones a migrated template per package process to
#                                speed the disposable-db ForEachEngine fixtures
#   OBSERVER_DBTEST_BASE_TEMPLATE optional pre-migrated base (unused here)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [[ -z "${OBSERVER_CONTROL_STORE_DSN:-}" ]]; then
  echo "org-postgres-suite: OBSERVER_CONTROL_STORE_DSN is empty." >&2
  echo "org-postgres-suite: refusing to run - without a live DSN every live-PG test skips," >&2
  echo "org-postgres-suite: which is the exact silent-skip gap this job exists to close." >&2
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
# Derive the package list at CI time so it never goes stale. The two-writer /
# concurrency suites (plan acceptance criterion 9) live in packages that
# declare a Test*TwoWriters function; grep for them under internal/orgserver +
# internal/aigateway. Then add the fixed baseline packages the task names:
# the two migration lineages + dbtest (db/...), the advisory-lock leader
# singleton (leader/...), the live control-store dialect suite
# (controlstore/...) and the ingest apply/receipt path (ingest/...).
# --------------------------------------------------------------------------
mapfile -t two_writer_pkgs < <(
  grep -rl "func Test.*TwoWriters" --include='*_test.go' internal/orgserver internal/aigateway \
    | xargs -r -n1 dirname \
    | sort -u \
    | sed 's#^#./#'
)
fixed_pkgs=(
  ./internal/orgserver/db/...
  ./internal/orgserver/leader/...
  ./internal/orgserver/controlstore/...
  ./internal/orgserver/ingest/...
)
mapfile -t packages < <(printf '%s\n' "${two_writer_pkgs[@]}" "${fixed_pkgs[@]}" | sort -u)

if [[ "${#two_writer_pkgs[@]}" -eq 0 ]]; then
  echo "org-postgres-suite: derived ZERO two-writer packages - the grep pattern drifted." >&2
  echo "org-postgres-suite: this must not happen; failing so the miss is loud." >&2
  exit 1
fi

echo "org-postgres-suite: ${#two_writer_pkgs[@]} two-writer package(s) + ${#fixed_pkgs[@]} fixed package glob(s):"
printf '  %s\n' "${packages[@]}"
echo "org-postgres-suite: log -> ${log}"

# -p 1 serializes the per-package test binaries: controltest.Open truncates a
# shared set of tables on the ONE live database, so package binaries running
# in parallel would truncate each other's in-flight rows (documented in
# scripts/controlstore-pg-harness.sh). Parallelism WITHIN a package is
# unaffected. -count=1 defeats the test cache. CGO stays disabled per the repo
# standard (modernc.org/sqlite is pure Go).
test_status=0
CGO_ENABLED="${CGO_ENABLED:-0}" go test -p 1 -count=1 -v "${packages[@]}" 2>&1 | tee "${log}" || test_status="${PIPESTATUS[0]}"

# --------------------------------------------------------------------------
# FAIL-IF-SKIPPED guard. In this job a live-PG test that skipped means the DSN
# did not reach it (a wiring regression) - a silent skip is worse than a
# failure because it looks green. Count SKIP lines whose test name matches a
# live-PG marker:
#   /postgres   - the ForEachEngine + controltest.Dialects "postgres" subtest
#   LivePG      - TestLivePG* (controlstore, leader, pgmigrations baseline/apply)
#   TwoWriters  - the concurrency suites (belt-and-braces; their PG halves are
#                 also caught by /postgres)
# --------------------------------------------------------------------------
skipped_live_pg="$(grep -E '^[[:space:]]*--- SKIP' "${log}" | grep -E 'LivePG|/postgres|TwoWriters' || true)"
skip_count=0
if [[ -n "${skipped_live_pg}" ]]; then
  skip_count="$(printf '%s\n' "${skipped_live_pg}" | grep -c . || true)"
fi

ran_live_pg="$(grep -Ec '^[[:space:]]*--- (PASS|FAIL): .*(LivePG|/postgres|TwoWriters)' "${log}" || true)"
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
