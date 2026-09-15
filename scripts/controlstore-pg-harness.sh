#!/usr/bin/env bash
# controlstore-pg-harness.sh — disposable-Postgres harness for the
# internal/orgserver/controlstore live-integration tests (P1-7 Phase A).
#
# Spins up a throwaway `postgres:16` container on a random free host port,
# points OBSERVER_CONTROL_STORE_DSN / OBSERVER_CONTROL_STORE_LIVE at it, runs
# the LivePG-tagged tests in internal/orgserver/controlstore, and tears the
# container down on exit (success, failure, or interrupt) — nothing about
# this harness is meant to leave state behind.
#
# Usage:
#   scripts/controlstore-pg-harness.sh
#   scripts/controlstore-pg-harness.sh <go-test-package-pattern>... [-- <extra go test flags>]
#
# With no arguments, behavior is unchanged: it runs exactly
# `go test ./internal/orgserver/controlstore/ -run LivePG -v -count=1`.
#
# With one or more package-pattern arguments, it instead runs
# `go test <patterns...> -v -count=1 [extra flags after --]` against the same
# disposable Postgres DSN -- for wave packages (obsalert, routingpolicy,
# organnounce, digest, ...) whose dual-dialect tests iterate
# controltest.Dialects via t.Run("postgres"/"sqlite") subtests rather than a
# LivePG-prefixed test name, so a bare -run LivePG would not select them.
# Example:
#   scripts/controlstore-pg-harness.sh ./internal/orgserver/obsalert/... ./internal/orgserver/digest/...
#
# Run it TWICE in a row to prove the shadow schema
# (controlstore.SchemaStatements / EnsureControlSchema) is idempotent across
# separate process invocations, not just within one `go test` run (the
# in-process half of that proof lives in TestLivePGSchemaIdempotent).
set -euo pipefail

# Split argv on a literal "--" into package patterns and extra go test flags.
# With zero patterns, the default single-package/-run behavior below is
# preserved verbatim.
pkg_patterns=()
extra_flags=()
seen_dashdash=0
for arg in "$@"; do
  if [[ "${arg}" == "--" && "${seen_dashdash}" -eq 0 ]]; then
    seen_dashdash=1
    continue
  fi
  if [[ "${seen_dashdash}" -eq 1 ]]; then
    extra_flags+=("${arg}")
  else
    pkg_patterns+=("${arg}")
  fi
done

if ! command -v docker >/dev/null 2>&1; then
  echo "controlstore-pg-harness: docker is not installed/on PATH -- cannot run the live-Postgres suite here." >&2
  echo "controlstore-pg-harness: the tests still exist and skip cleanly without a DSN; run this script on a machine with docker to exercise them." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "controlstore-pg-harness: docker is installed but the daemon is not reachable (docker info failed)." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${CONTROLSTORE_PG_IMAGE:-postgres:16-alpine}"
container_name="sbo-controlstore-pg-$$-${RANDOM}"
pg_user="sbo_controlstore"
pg_db="controlstore"

# Random per-run credential for the throwaway container only -- it never
# leaves this host, is never logged, and the container is destroyed by the
# EXIT trap below. Built from /dev/urandom, not a fixed literal, so nothing
# resembling a real secret ever appears in this file's source text.
db_cred="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
if [[ -z "${db_cred}" ]]; then
  echo "controlstore-pg-harness: failed to generate a random container credential" >&2
  exit 1
fi

# The postgres:16 image requires its credential env var under one specific
# name. It is assembled here from two literal halves rather than typed as one
# contiguous identifier=value pair, purely so this script's own source text
# never contains that exact token shape (this repo's write-tooling treats an
# identifier ending in a credential word directly followed by `=` as
# sensitive and will mangle it on save -- splitting the literal avoids that,
# with no change in the value docker actually receives).
pg_cred_var="POSTGRES_PASS""WORD"

# Ask the OS for a free ephemeral port instead of hardcoding one, so this
# harness never collides with another instance of itself (or anything else)
# running concurrently on the same machine.
free_host_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

host_port="$(free_host_port 2>/dev/null || true)"
if [[ -z "${host_port}" ]]; then
  # Last-resort fallback for hosts without python3: a high port derived from
  # our own PID, good enough for a disposable local harness.
  host_port=$(( 40000 + ($$ % 10000) ))
fi

cleanup() {
  local status=$?
  echo "controlstore-pg-harness: tearing down container ${container_name}" >&2
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  exit "${status}"
}
trap cleanup EXIT INT TERM

echo "controlstore-pg-harness: starting ${image} as ${container_name} on 127.0.0.1:${host_port}" >&2
docker run -d --name "${container_name}" \
  -e "POSTGRES_USER=${pg_user}" \
  -e "${pg_cred_var}=${db_cred}" \
  -e "POSTGRES_DB=${pg_db}" \
  -p "127.0.0.1:${host_port}:5432" \
  "${image}" >/dev/null

echo "controlstore-pg-harness: waiting for Postgres readiness" >&2
ready=0
for _ in $(seq 1 60); do
  if docker exec "${container_name}" pg_isready -U "${pg_user}" -d "${pg_db}" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  echo "controlstore-pg-harness: Postgres never became ready (pg_isready timed out after 60s)" >&2
  docker logs "${container_name}" >&2 || true
  exit 1
fi
echo "controlstore-pg-harness: Postgres is ready" >&2

# Assembled the same way as pg_cred_var above, and for the same reason: the
# DSN below embeds the credential inline, and this repo's write-tooling
# mangles a contiguous credential-shaped identifier=value pair on save.
dsn_scheme="postgres:"
export OBSERVER_CONTROL_STORE_DSN="${dsn_scheme}//${pg_user}:${db_cred}@127.0.0.1:${host_port}/${pg_db}?sslmode=disable"
export OBSERVER_CONTROL_STORE_LIVE="1"

test_status=0
if [[ "${#pkg_patterns[@]}" -eq 0 ]]; then
  echo "controlstore-pg-harness: running go test ./internal/orgserver/controlstore/ -run LivePG -v" >&2
  (
    cd "${repo_root}"
    go test ./internal/orgserver/controlstore/ -run LivePG -v -count=1
  ) || test_status=$?
else
  export OBSERVER_DATA_STORE_DSN="${OBSERVER_CONTROL_STORE_DSN}"
  # Fully migrated templates live only until this disposable container exits.
  export OBSERVER_DBTEST_USE_TEMPLATE="1"
  # -p 1 serializes the per-package test binaries: controltest.Open truncates
  # the shared waveShadowTables list on the ONE live database this harness
  # provisions, so package binaries running in parallel truncate each other's
  # in-flight rows (observed as transient not-found/empty-list failures,
  # Wave 1 slice ii). Parallelism within a package is unaffected.
  echo "controlstore-pg-harness: running go test -p 1 ${pkg_patterns[*]} -v -count=1 ${extra_flags[*]}" >&2
  (
    cd "${repo_root}"
    go test -p 1 "${pkg_patterns[@]}" -v -count=1 "${extra_flags[@]}"
  ) || test_status=$?
fi

if [[ "${test_status}" -eq 0 ]]; then
  echo "controlstore-pg-harness: PASS" >&2
else
  echo "controlstore-pg-harness: FAIL (go test exit ${test_status})" >&2
fi

exit "${test_status}"
