#!/usr/bin/env bash
# scripts/rehearsal/migrate-rehearsal.sh - the org PostgreSQL migration
# rehearsal harness (managed-SaaS plan 07 row M3a.5). Runbook:
# docs/migration-rehearsal-runbook.md. First report:
# docs/audits/r2-baseline-rehearsal-2026-11-13.md.
#
# It rehearses `observer-org migrate` against a COPY of a database on a
# throwaway PostgreSQL container: exact row counts per table before and after,
# the `upgrade preflight` estimate beside the measured time of every step
# (from the server's statement log), one migrate killed mid-step and resumed,
# and a schema comparison with a database the same binary migrated from empty.
# It can also fill a fresh database through the REAL node wire with
# cmd/observer-loadtest driven against an older (N-1) server binary, and check
# a migrated database by serving it with the new (N) binary under load.
#
# Usage (every subcommand reads the REH_* variables below):
#   migrate-rehearsal.sh logging                    statement logging on the container (once)
#   migrate-rehearsal.sh fresh    DB PREFIX         create an empty database
#   migrate-rehearsal.sh restore  DB PREFIX DUMP    create a database from a pg_dump -Fc file
#   migrate-rehearsal.sh load     DB                N-1: migrate, serve, provision, push rows, verify
#   migrate-rehearsal.sh rehearse DB [STEP]         N: counts, preflight, migrate (killed during STEP
#                                                   and resumed when STEP is given), counts, step times
#   migrate-rehearsal.sh drain    DB [prev|n]       restart that server and apply its unapplied log
#   migrate-rehearsal.sh migrate  DB                N: a plain migrate (the empty reference for schemadiff)
#   migrate-rehearsal.sh schemadiff DB REFDB        compare DB's schema with REFDB's
#   migrate-rehearsal.sh serve-check DB             N: serve DB, push rows through every family, verify
#   migrate-rehearsal.sh counts   DB FILE           exact per-table row counts
#
# Every database is created with its own sbo.role_prefix (PREFIX), because the
# tenancy roles are cluster-wide (0186) and several copies share one cluster.
#
# THROWAWAY ONLY. It drops nothing it did not create, but it runs servers with
# dev sign-in and writes load-test rows. Never point it at a server or a
# database anyone else uses.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: keep container paths intact

: "${REH_PG_CONTAINER:?REH_PG_CONTAINER names the throwaway PostgreSQL container}"
: "${REH_PG_USER:=observer}"
: "${REH_PG_PASSWORD:=x}"
: "${REH_PG_HOSTPORT:=127.0.0.1:55463}"
: "${REH_OUT:=rehearsal-out}"
: "${REH_BIN:=observer-org}"           # N: the binary under test (migrate, preflight, serve-check)
: "${REH_BIN_PREV:=}"                  # N-1: the binary that built the old schema (load)
: "${REH_LOADTEST:=observer-loadtest}" # cmd/observer-loadtest
: "${REH_ORG_PORT:=18443}"
: "${REH_METRICS_PORT:=19464}"
# load: the synthetic fleet. ROWS is a target; the run stops at its hold.
: "${REH_LOAD_NODES:=100}"
: "${REH_LOAD_MIX:=heavy=100}"
: "${REH_LOAD_BUSY:=25}"
: "${REH_LOAD_HOLD:=10m}"
: "${REH_LOAD_PUSH_EVERY:=10s}"
: "${REH_LOAD_TOOL_BODIES:=true}"
# rehearse: how long the killed step runs before the kill (seconds).
: "${REH_INTERRUPT_DELAY:=1}"

winpath() { if command -v cygpath > /dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

mkdir -p "$REH_OUT"
# On Git Bash the binaries are Windows programs: give them C:/... paths, which
# bash accepts too (and MSYS_NO_PATHCONV stops it rewriting arguments).
OUT="$(winpath "$(cd "$REH_OUT" && pwd)")"
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
secs() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

psql_db() {
  local db="$1"
  shift
  docker exec -i "$REH_PG_CONTAINER" psql -U "$REH_PG_USER" -d "$db" -v ON_ERROR_STOP=1 -X -At "$@"
}
dsn() { printf 'postgres://%s:%s@%s/%s?sslmode=disable' "$REH_PG_USER" "$REH_PG_PASSWORD" "$REH_PG_HOSTPORT" "$1"; }

# The exact row count of every table in public (pg_class reltuples is only an
# estimate, and the comparison must be exact).
COUNTS_SQL="SELECT c.relname || '|' || (xpath('/row/n/text()', query_to_xml(format('SELECT count(*) AS n FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]::text
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') ORDER BY c.relname"

counts() { psql_db "$1" -c "$COUNTS_SQL" > "$2"; }

# render_config STATE_DIR FILE: a dev config for a throwaway server, with
# dev keys made once under $OUT/keys (deploy/observer-org/keygen.sh's shapes).
render_config() {
  local state="$1" file="$2" keys="$OUT/keys"
  if [ ! -f "$keys/session.key" ]; then
    mkdir -p "$keys/bearer" "$keys/policy" "$keys/scim"
    local k
    for k in "$keys/bearer/signing.key" "$keys/policy/signing.key"; do
      {
        printf '%s\n' '-----BEGIN PRIVATE KEY-----'
        printf '%s' 'MC4CAQAwBQYDK2VwBCIE'
        { printf ' '; head -c 32 /dev/urandom; } | base64
        printf '%s\n' '-----END PRIVATE KEY-----'
      } > "$k"
    done
    head -c 32 /dev/urandom > "$keys/session.key"
    printf '%s' "rehearsal-scim-token" > "$keys/scim/token"
    chmod 600 "$keys/session.key" "$keys/bearer/signing.key" "$keys/policy/signing.key" "$keys/scim/token"
  fi
  mkdir -p "$state"
  local s k2
  s="$(winpath "$state")"
  k2="$(winpath "$keys")"
  cat > "$file" << EOF
[server]
listen = "127.0.0.1:$REH_ORG_PORT"
external_url = "http://127.0.0.1:$REH_ORG_PORT"
state_dir = "$s"
sealing_key_path = "$s/insight-secret.key"
session_key_path = "$k2/session.key"
dev_auth = true
log_level = "warn"

[auth]
providers = ["local"]

[log]
engine = "embedded"

[scim]
auth_token_path = "$k2/scim/token"

[bearer]
signing_key_path = "$k2/bearer/signing.key"
default_lifetime_days = 90

[policy]
signing_key_path = "$k2/policy/signing.key"

[enrolment]
default_token_lifetime_days = 7

[dashboard]
admin_emails = ["admin@example.com"]

[metrics]
listen = "127.0.0.1:$REH_METRICS_PORT"
EOF
}

# serve_with BIN DB TAG: start BIN serve against DB in the background and wait
# for /readyz; SERVER_PID is the process to stop with stop_server.
serve_with() {
  local bin="$1" db="$2" tag="$3"
  local state="$OUT/state-$tag" cfg="$OUT/config-$tag.toml"
  render_config "$state" "$cfg"
  OBSERVER_CONTROL_STORE_DSN="$(dsn "$db")" OBSERVER_DATA_STORE_DSN="$(dsn "$db")" \
    "$bin" --config "$cfg" serve > "$OUT/server-$tag.log" 2>&1 &
  SERVER_PID=$!
  local i
  for i in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$REH_ORG_PORT/readyz" > "$OUT/readyz-$tag.json" 2>&1; then
      log "server $tag ready (pid $SERVER_PID)"
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2> /dev/null; then break; fi
    sleep 1
  done
  log "server $tag did not become ready; last log lines:"
  tail -20 "$OUT/server-$tag.log" >&2
  return 1
}
stop_server() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2> /dev/null || true
    wait "$SERVER_PID" 2> /dev/null || true
    SERVER_PID=""
  fi
}

# drain_log: wait until the server's durable log has nothing left to apply
# (observer_org_log_pending = 0). Acknowledged pushes sit in the log until the
# apply worker writes them, so counting or stopping before this loses nothing
# but reports rows as missing. REH_DRAIN_MAX bounds the wait (seconds).
drain_log() {
  local i p=""
  for i in $(seq 1 "${REH_DRAIN_MAX:-3600}"); do
    p="$(curl -fsS "http://127.0.0.1:$REH_METRICS_PORT/metrics" 2> /dev/null |
      awk '/^observer_org_log_pending[ {]/ { s += $NF; f = 1 } END { if (f) print s + 0 }')"
    if [ "$p" = "0" ]; then
      log "server log drained"
      return 0
    fi
    [ $((i % 60)) = 0 ] && log "server log pending: ${p:-unknown}"
    sleep 1
  done
  log "server log still pending after ${REH_DRAIN_MAX:-3600}s: ${p:-unknown}"
  return 1
}

# push_load DB TAG STEPS: provision REH_LOAD_NODES developers and push rows
# through the real node wire, then reconcile the server's acknowledgements
# with the rows in PostgreSQL (`observer-loadtest verify`: zero loss).
push_load() {
  local db="$1" tag="$2" steps="$3"
  # A run id per invocation: row ids carry it, and verify counts by it, so a
  # second load into the same database must not share the first one's.
  local run="$tag-$(date -u +%H%M%S)"
  local dir="$OUT/load-$run"
  mkdir -p "$dir"
  dsn "$db" > "$dir/dsn"
  # The dev sign-in needs an active member; create the admin the way
  # `observer-org quickstart` does (a 409 on a second run is fine).
  curl -sS -o "$dir/scim-admin.json" -X POST "http://127.0.0.1:$REH_ORG_PORT/scim/v2/Users" \
    -H "Authorization: Bearer $(cat "$OUT/keys/scim/token")" -H 'Content-Type: application/scim+json' \
    -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"admin@example.com","emails":[{"value":"admin@example.com","primary":true}],"active":true}'
  "$REH_LOADTEST" provision --org-url "http://127.0.0.1:$REH_ORG_PORT" --state "$dir/state.json" \
    --count "$REH_LOAD_NODES" --scim-token-file "$OUT/keys/scim/token" --admin dev-auth:admin@example.com \
    --concurrency 4 > "$dir/provision.log" 2>&1
  "$REH_LOADTEST" run --state "$dir/state.json" --out "$dir/run" --steps "$steps" \
    --mix "$REH_LOAD_MIX" --busy "$REH_LOAD_BUSY" --tool-bodies="$REH_LOAD_TOOL_BODIES" \
    --push-every "$REH_LOAD_PUSH_EVERY" --ramp-in 10s --admins 1 --admin dev-auth:admin@example.com \
    --no-probes --no-rails --metrics-url "http://127.0.0.1:$REH_METRICS_PORT/metrics" \
    --drain-timeout 3m --settle-timeout 10m --run-id "$run" > "$dir/run.log" 2>&1 || {
    log "loadtest run exited non-zero (a pass-limit verdict is informational here); see $dir/run.log"
  }
  drain_log
  "$REH_LOADTEST" verify --dsn-file "$dir/dsn" --ledger "$dir/run/ledger.json" | tee "$dir/verify.txt"
}

# step_times DB LOGFILE: one row per step body the server logged
# (log_min_duration_statement = 0): the body's time, its commit's time and the
# step its per-step record names. A body with no record is an attempt that
# never committed (the killed run).
step_times() {
  local db="$1" file="$2"
  awk -v db="db=$db" '
    index($0, db) == 0 { next }
    {
      pid = $3
      match($0, /xid=[0-9]+/); xid = substr($0, RSTART + 4, RLENGTH - 4)
    }
    /LOG:  duration: [0-9.]+ ms  statement: -- / && !/statement: -- ping/ {
      match($0, /duration: [0-9.]+/); d = substr($0, RSTART + 10, RLENGTH - 10)
      n++; body[n] = d; bxid[n] = xid; bts[n] = $1 " " $2; last[pid] = n
      next
    }
    /DETAIL:  parameters: \$1 = .migration:[0-9]+/ {
      match($0, /migration:[0-9]+/); v = substr($0, RSTART + 10, RLENGTH - 10)
      for (i = n; i >= 1; i--) if (bxid[i] == xid) { if (!(i in step)) step[i] = v; break }
      next
    }
    /LOG:  duration: [0-9.]+ ms  statement: commit/ {
      match($0, /duration: [0-9.]+/); d = substr($0, RSTART + 10, RLENGTH - 10)
      if ((pid in last) && !(last[pid] in commit)) commit[last[pid]] = d
      next
    }
    END {
      printf "%-6s %-12s %12s %10s %12s\n", "step", "logged", "body ms", "commit ms", "total s"
      for (i = 1; i <= n; i++) {
        s = (i in step) ? sprintf("%04d", step[i]) : "abort"
        c = (i in commit) ? commit[i] : 0
        printf "%-6s %-12s %12.1f %10.1f %12.2f\n", s, substr(bts[i], 12, 12), body[i], c, (body[i] + c) / 1000
      }
    }' "$file"
}

# pending_steps FILE: the step files a preflight report says would run.
pending_steps() {
  awk '/control migrations/ { on = 1; next } on && /^[A-Z]+ / { exit } on { gsub(/^ +/, ""); if ($0 ~ /^[0-9][0-9][0-9][0-9]_.*\.sql$/) print substr($0, 1, 4) }' "$1"
}

# cmd_drain DB [prev|n]: restart the server that loaded DB on its own state
# directory (so its embedded log is the one with the unapplied records), wait
# for the log to drain, and stop it.
cmd_drain() {
  local db="$1" which="${2:-prev}" bin="$REH_BIN"
  [ "$which" = prev ] && bin="$REH_BIN_PREV"
  trap stop_server EXIT
  serve_with "$bin" "$db" "$which-$db"
  drain_log
  stop_server
}

cmd_logging() {
  psql_db postgres -c "ALTER SYSTEM SET log_line_prefix = '%m [%p] xid=%x db=%d '" -c "SELECT pg_reload_conf()" > /dev/null
  log "statement log prefix set on $REH_PG_CONTAINER"
}

cmd_fresh() {
  local db="$1" prefix="$2"
  psql_db postgres -c "CREATE DATABASE \"$db\" OWNER \"$REH_PG_USER\"" \
    -c "ALTER DATABASE \"$db\" SET sbo.role_prefix = '$prefix'" > /dev/null
  log "created $db (role prefix $prefix)"
}

cmd_restore() {
  local db="$1" prefix="$2" dump="$3"
  cmd_fresh "$db" "$prefix"
  docker cp "$dump" "$REH_PG_CONTAINER:/tmp/rehearsal-$db.dump"
  local t0
  t0="$(secs)"
  docker exec "$REH_PG_CONTAINER" pg_restore -U "$REH_PG_USER" -d "$db" --exit-on-error "/tmp/rehearsal-$db.dump"
  docker exec "$REH_PG_CONTAINER" rm -f "/tmp/rehearsal-$db.dump"
  log "restored $dump into $db in $(elapsed "$t0" "$(secs)")s"
}

cmd_load() {
  local db="$1"
  [ -n "$REH_BIN_PREV" ] || {
    echo "load needs REH_BIN_PREV (the N-1 binary)" >&2
    exit 2
  }
  local cfg="$OUT/config-prev-$db.toml"
  render_config "$OUT/state-prev-$db" "$cfg"
  OBSERVER_CONTROL_STORE_DSN="$(dsn "$db")" "$REH_BIN_PREV" --config "$cfg" migrate | tee "$OUT/$db.prev-migrate.txt"
  trap stop_server EXIT
  serve_with "$REH_BIN_PREV" "$db" "prev-$db"
  push_load "$db" "prev-$db" "$REH_LOAD_NODES@$REH_LOAD_HOLD"
  stop_server
  counts "$db" "$OUT/$db.loaded.txt"
  log "$db holds $(awk -F'|' '{ s += $2 } END { print s }' "$OUT/$db.loaded.txt") rows after the load"
}

cmd_rehearse() {
  local db="$1" target="${2:-}"
  local cfg="$OUT/config-n-$db.toml" d
  d="$(dsn "$db")"
  render_config "$OUT/state-n-$db" "$cfg"

  counts "$db" "$OUT/$db.before.txt"
  psql_db "$db" -c "SELECT pg_database_size(current_database())" > "$OUT/$db.size.before"
  OBSERVER_CONTROL_STORE_DSN="$d" "$REH_BIN" --config "$cfg" upgrade preflight --skip-backup > "$OUT/$db.preflight.txt" 2>&1 || true
  pending_steps "$OUT/$db.preflight.txt" > "$OUT/$db.pending.txt"
  log "$db: $(wc -l < "$OUT/$db.pending.txt") pending steps; $(awk -F'|' '{ s += $2 } END { print s }' "$OUT/$db.before.txt") rows"

  psql_db postgres -c "ALTER DATABASE \"$db\" SET log_min_duration_statement = 0" > /dev/null
  local since t0 t1 rc=0
  since="$(now)"
  sleep 1
  t0="$(secs)"
  if [ -n "$target" ]; then
    local prev
    prev="$(awk -v t="$target" '$1 == t { print p; exit } { p = $1 }' "$OUT/$db.pending.txt")"
    [ -n "$prev" ] || {
      echo "rehearse: step $target is not pending after another pending step" >&2
      exit 2
    }
    OBSERVER_CONTROL_STORE_DSN="$d" "$REH_BIN" --config "$cfg" migrate > "$OUT/$db.migrate-killed.txt" 2>&1 &
    local mpid=$! seen=0 i
    for i in $(seq 1 6000); do
      if psql_db "$db" -c "SELECT 1 FROM schema_meta WHERE key = 'migration:$((10#$prev))'" 2> /dev/null | grep -q 1; then
        seen=1
        break
      fi
      kill -0 "$mpid" 2> /dev/null || break
      sleep 0.1
    done
    [ "$seen" = 1 ] || {
      echo "rehearse: step $prev never committed; see $OUT/$db.migrate-killed.txt" >&2
      exit 1
    }
    sleep "$REH_INTERRUPT_DELAY"
    # What the in-flight step holds at the moment of the kill.
    psql_db "$db" -c "SELECT l.mode, count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid)
      WHERE a.datname = current_database() AND a.pid <> pg_backend_pid() AND a.backend_type = 'client backend'
        AND l.locktype = 'relation' GROUP BY 1 ORDER BY 1" > "$OUT/$db.locks-at-kill.txt" || true
    kill -9 "$mpid" 2> /dev/null || true
    wait "$mpid" 2> /dev/null || true
    local tk
    tk="$(secs)"
    log "$db: killed migrate $(elapsed "$t0" "$tk")s in, $REH_INTERRUPT_DELAY s into step $target"
    psql_db "$db" -c "SELECT key FROM schema_meta WHERE key LIKE 'migration:%' ORDER BY length(key), key" > "$OUT/$db.ledger-after-kill.txt"
    if grep -qx "migration:$((10#$target))" "$OUT/$db.ledger-after-kill.txt"; then
      log "$db: step $target committed before the kill landed: the kill was NOT mid-step (raise the data size or lower REH_INTERRUPT_DELAY)"
      echo "missed" > "$OUT/$db.interrupt.txt"
    else
      echo "mid-step" > "$OUT/$db.interrupt.txt"
    fi
    # The killed client's backend runs on until it next talks to the socket;
    # it holds the step's locks and the migration lock until then.
    psql_db "$db" -c "SELECT pid, state, now() - query_start FROM pg_stat_activity
      WHERE datname = current_database() AND pid <> pg_backend_pid() AND backend_type = 'client backend'" > "$OUT/$db.backend-after-kill.txt" || true
    local tr
    tr="$(secs)"
    OBSERVER_CONTROL_STORE_DSN="$d" "$REH_BIN" --config "$cfg" migrate > "$OUT/$db.migrate.txt" 2>&1 || rc=$?
    log "$db: resumed migrate finished in $(elapsed "$tr" "$(secs)")s (rc=$rc)"
  else
    OBSERVER_CONTROL_STORE_DSN="$d" "$REH_BIN" --config "$cfg" migrate > "$OUT/$db.migrate.txt" 2>&1 || rc=$?
  fi
  t1="$(secs)"
  sleep 1
  psql_db postgres -c "ALTER DATABASE \"$db\" RESET log_min_duration_statement" > /dev/null
  docker logs --since "$since" "$REH_PG_CONTAINER" > "$OUT/$db.pglog.txt" 2>&1
  step_times "$db" "$OUT/$db.pglog.txt" > "$OUT/$db.steps.txt"
  echo "wall $(elapsed "$t0" "$t1")s rc=$rc" > "$OUT/$db.wall.txt"
  cat "$OUT/$db.migrate.txt"
  [ "$rc" = 0 ] || exit "$rc"

  counts "$db" "$OUT/$db.after.txt"
  psql_db "$db" -c "SELECT pg_database_size(current_database())" > "$OUT/$db.size.after"
  # Every table that existed before must hold the same rows after; new tables
  # and the ledger are listed separately.
  join -t'|' -a1 -a2 -e MISSING -o 0,1.2,2.2 "$OUT/$db.before.txt" "$OUT/$db.after.txt" |
    awk -F'|' '$2 != $3 { print }' > "$OUT/$db.count-diff.txt"
  log "$db: $(cat "$OUT/$db.wall.txt"); tables whose count changed or that are new:"
  cat "$OUT/$db.count-diff.txt" >&2
}

cmd_migrate() {
  local db="$1" cfg="$OUT/config-n-$1.toml"
  render_config "$OUT/state-n-$db" "$cfg"
  OBSERVER_CONTROL_STORE_DSN="$(dsn "$db")" "$REH_BIN" --config "$cfg" migrate
}

cmd_schemadiff() {
  local db="$1" ref="$2" pa pb
  pa="$(psql_db "$db" -c "SELECT sbo_tenancy_role('owner')" | sed 's/_owner$//')"
  pb="$(psql_db "$ref" -c "SELECT sbo_tenancy_role('owner')" | sed 's/_owner$//')"
  # Normalise the role prefixes (the six role names and the literal 0186 bakes
  # into sbo_tenancy_role) and drop what differs by construction (the dump
  # header, \restrict keys, database-level settings).
  local norm='/^--/d; /^\\(un)?restrict /d; /^$/d; /^SET /d; /^SELECT pg_catalog.set_config/d'
  local kinds='(owner|migrator|rt|host|ops|ctx)'
  docker exec "$REH_PG_CONTAINER" pg_dump -U "$REH_PG_USER" -d "$db" --schema-only --no-owner |
    sed -E "s/\b${pa}_${kinds}\b/PFX_\1/g; s/'${pa}' \|\| '_'/'PFX' || '_'/; $norm" > "$OUT/$db.schema.sql"
  docker exec "$REH_PG_CONTAINER" pg_dump -U "$REH_PG_USER" -d "$ref" --schema-only --no-owner |
    sed -E "s/\b${pb}_${kinds}\b/PFX_\1/g; s/'${pb}' \|\| '_'/'PFX' || '_'/; $norm" > "$OUT/$ref.schema.sql"
  if diff -u "$OUT/$ref.schema.sql" "$OUT/$db.schema.sql" > "$OUT/$db.vs.$ref.schema.diff"; then
    log "schema of $db equals $ref"
  else
    log "schema of $db differs from $ref: $(grep -c '^[-+][^-+]' "$OUT/$db.vs.$ref.schema.diff") lines ($OUT/$db.vs.$ref.schema.diff)"
  fi
}

cmd_serve_check() {
  local db="$1"
  trap stop_server EXIT
  serve_with "$REH_BIN" "$db" "n-$db"
  push_load "$db" "n-$db" "${REH_CHECK_NODES:-10}@${REH_CHECK_HOLD:-2m}"
  stop_server
  if grep -E -i 'level=(ERROR|error)' "$OUT/server-n-$db.log" > "$OUT/$db.server-errors.txt"; then
    log "$db: the N server logged $(wc -l < "$OUT/$db.server-errors.txt") error lines ($OUT/$db.server-errors.txt)"
  fi
}

sub="${1:-}"
shift || true
case "$sub" in
  logging) cmd_logging ;;
  fresh) cmd_fresh "$@" ;;
  restore) cmd_restore "$@" ;;
  load) cmd_load "$@" ;;
  rehearse) cmd_rehearse "$@" ;;
  migrate) cmd_migrate "$@" ;;
  drain) cmd_drain "$@" ;;
  schemadiff) cmd_schemadiff "$@" ;;
  serve-check) cmd_serve_check "$@" ;;
  counts) counts "$@" ;;
  *)
    sed -n '2,30p' "$0"
    exit 2
    ;;
esac
