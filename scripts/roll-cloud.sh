#!/usr/bin/env bash
# roll-cloud.sh — update the running Cloud Intelligence image after a code
# change (pre-roll gate + rebuild + push + roll both Container Apps + verify
# live). Env-parameterized (D3 / gap 4.5): SBCI_ENV selects staging (default,
# byte-identical to every prior behaviour of this script) or prod.
#
# This is the "update" half of the cloud estate lifecycle. Provisioning
# (create/delete the estate) lives in scripts/cloudintel/cloudintel-azure.sh;
# this script ONLY rolls a new image onto the already-provisioned apps.
#
#   scripts/roll-cloud.sh <version>                     pre-roll gate + build + push :<version> + roll api+worker + verify
#   scripts/roll-cloud.sh <version> --skip-build         roll an ALREADY-pushed :<version> (still runs the pre-roll gate)
#   scripts/roll-cloud.sh <version> --allow-schema-ahead roll even though the embedded migration head is ahead of the deployed schema
#   scripts/roll-cloud.sh rollback <version>             point api+worker back at an existing :<version> (no FULL pre-roll gate — the
#                                                         image already ran — but an INFORMATIONAL schema check still runs; P3-g)
#   scripts/roll-cloud.sh rollback <version> --yes       required when that schema check reports rc=3 (deployed schema is ahead of
#                                                         CURRENT HEAD — the usual shape of a rollback); refused without it
#
# Example (today's roll):  scripts/roll-cloud.sh v7
# Example (prod):           SBCI_ENV=prod SBCI_PG_DSN=... scripts/roll-cloud.sh v1
#
# Mechanics (Container Apps — a clean in-place image update, NO recreate):
#   0. PRE-ROLL GATE (D3 / gap 4.5) — go build, go vet, the webcloud dist-drift
#      gate IF it exists, and a schema pre-check IF a deployed-DB DSN is
#      available. See pre_roll_gate() below.
#   1. git archive HEAD -> a clean dir (so the build matches the commit, never
#      the dirty working tree; Dockerfile.observer-cloud embeds webcloud/dist).
#   2. az acr build -r <acr> -f Dockerfile.observer-cloud
#        -t sbci-api:<v> -t sbci-worker:<v> .   (builds + pushes server-side)
#   3. az containerapp update --image ... for sbci-api AND sbci-worker.
#   4. Poll the portal + /v1/auth/nonce for 200.
#
# Requires: az logged in (Linux az works for this RG), git clean-ish HEAD is
# what gets built (uncommitted changes are IGNORED by design — commit first).
set -euo pipefail

SBCI_ENV="${SBCI_ENV:-staging}"
case "$SBCI_ENV" in
    staging | prod) ;;
    *)
        echo "roll-cloud: SBCI_ENV must be 'staging' or 'prod' (got '$SBCI_ENV')" >&2
        exit 2
        ;;
esac

if [ "$SBCI_ENV" = "prod" ]; then
    RG="${RG:-superbased-cloudintel-prod-rg}"
    PUBLIC_HOST="${PUBLIC_HOST:-cloud.superbased.app}"
else
    RG="${RG:-superbased-cloudintel-staging-rg}"
    # staging answers on its own hostname since the 2026-09-14 cut-over
    # (runbook s14.1 step 6); cloud.superbased.app is production.
    PUBLIC_HOST="${PUBLIC_HOST:-staging-cloud.superbased.app}"
fi
ACR="${ACR:-sbdemoacr35022}"
REG="$ACR.azurecr.io"
API_APP=sbci-api
WORKER_APP=sbci-worker
PORTAL_URL="https://${PUBLIC_HOST}/portal"
NONCE_URL="https://${PUBLIC_HOST}/v1/auth/nonce"

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

die() { echo "roll-cloud: $*" >&2; exit 1; }
note() { echo "roll-cloud: $*"; }

# resolve_pg_dsn prints the deployed-DB DSN to stdout (SBCI_PG_DSN, or
# resolved read-only from Key Vault via SBCI_PG_DSN_KV_NAME/
# SBCI_PG_DSN_KV_SECRET), or nothing if neither is configured. Shared by
# pre_roll_gate (forward roll) and the rollback schema-check (P3-g) so the
# two DSN-resolution paths never drift apart.
resolve_pg_dsn() {
    local dsn="${SBCI_PG_DSN:-}"
    if [ -z "$dsn" ] && [ -n "${SBCI_PG_DSN_KV_SECRET:-}" ] && [ -n "${SBCI_PG_DSN_KV_NAME:-}" ]; then
        note "resolving the deployed-schema DSN from Key Vault ($SBCI_PG_DSN_KV_NAME/$SBCI_PG_DSN_KV_SECRET) — read-only" >&2
        dsn=$(az keyvault secret show --vault-name "$SBCI_PG_DSN_KV_NAME" --name "$SBCI_PG_DSN_KV_SECRET" \
            --query value -o tsv 2>/dev/null | tr -d '\r\n') || dsn=""
    fi
    printf '%s' "$dsn"
}

# pre_roll_gate (D3 / gap 4.5) — refuses a bad roll BEFORE any az call. Every
# step below is a local, side-effect-free check; nothing here touches Azure.
#
#   1. `go build ./cmd/observer-cloud` — the binary that will be baked into
#      the image must at least compile against the CURRENT working tree (the
#      image itself builds from `git archive HEAD`, i.e. the committed tree —
#      this step catches an uncommitted-but-about-to-be-committed break early,
#      and is the same tree schema-check below builds from).
#   2. `go vet ./cmd/observer-cloud/... ./internal/cloudserver/...`
#   3. scripts/verify-webcloud-dist.sh — ONLY if it exists (a later wave may
#      add it; this script never assumes it). Loudly prints a skip line
#      otherwise so an operator can't mistake silence for "checked, and clean".
#   4. observer-cloud schema-check against the deployed DSN — ONLY if a DSN is
#      available (SBCI_PG_DSN env var, or a Key Vault secret name via
#      SBCI_PG_DSN_KV_SECRET when the operator is az-logged-in). Exit 2 means
#      the embedded migration head is AHEAD of the deployed schema (a
#      migration is owed) — refused unless --allow-schema-ahead. Exit 3 means
#      the embedded head is BEHIND the deployed schema (this image is older
#      than the database) — ALWAYS refused, no override; rolling stale code
#      against a newer schema is not a documented-safe path. No DSN available
#      -> printed instruction, gate step skipped (not silently passed).
pre_roll_gate() {
    local allow_schema_ahead="$1"
    echo "== pre-roll gate =="

    note "go build ./cmd/observer-cloud"
    go build -o /dev/null ./cmd/observer-cloud || die "pre-roll gate: go build failed — fix the build before rolling"

    note "go vet ./cmd/observer-cloud/... ./internal/cloudserver/..."
    go vet ./cmd/observer-cloud/... ./internal/cloudserver/... || die "pre-roll gate: go vet failed — fix the vet findings before rolling"

    if [ -x "scripts/verify-webcloud-dist.sh" ] || [ -f "scripts/verify-webcloud-dist.sh" ]; then
        note "scripts/verify-webcloud-dist.sh"
        bash scripts/verify-webcloud-dist.sh || die "pre-roll gate: webcloud dist drifted from src — rebuild and commit webcloud/dist before rolling"
    else
        note "scripts/verify-webcloud-dist.sh not present — dist gate not present, skipped"
    fi

    local dsn
    dsn=$(resolve_pg_dsn)

    if [ -z "$dsn" ]; then
        note "schema pre-check SKIPPED — no deployed-DB DSN available."
        note "  Set SBCI_PG_DSN=<bare postgresql://... DSN> to run it, or SBCI_PG_DSN_KV_NAME +"
        note "  SBCI_PG_DSN_KV_SECRET to resolve one read-only from Key Vault (az login required)."
        note "  Manual check: build observer-cloud from this commit, then run"
        note "  'SBCI_PG_DSN=<dsn> observer-cloud schema-check' against the deployed database yourself"
        note "  before rolling, or accept the risk of a migration-owed roll."
        return 0
    fi

    local bin rc=0
    bin=$(mktemp)
    if ! go build -o "$bin" ./cmd/observer-cloud; then
        rm -f "$bin"
        die "pre-roll gate: go build (for schema-check) failed"
    fi

    note "observer-cloud schema-check (against the deployed schema)"
    SBCI_PG_DSN="$dsn" "$bin" schema-check || rc=$?
    rm -f "$bin"

    case "$rc" in
        0) note "schema-check: OK — deployed schema matches this commit's embedded migration head" ;;
        2)
            if [ "$allow_schema_ahead" = "1" ]; then
                note "schema-check: embedded head is AHEAD of the deployed schema — proceeding (--allow-schema-ahead)"
            else
                die "pre-roll gate: embedded migration head is AHEAD of the deployed schema (a migration is owed)." \
                    " Run 'observer-cloud migrate' against the deployed database first (see runbook §12c/§12f)," \
                    " or pass --allow-schema-ahead to roll anyway (NOT recommended if this image reads/writes the new columns)."
            fi
            ;;
        3)
            die "pre-roll gate: embedded migration head is BEHIND the deployed schema — this image is OLDER than" \
                " the database. Roll a newer commit instead; there is no override for this direction."
            ;;
        *)
            die "pre-roll gate: observer-cloud schema-check exited $rc (unexpected — check the DSN and connectivity)"
            ;;
    esac
}

# rollback_schema_check (P3-g) — rollback has no way to build the TARGET
# commit's own binary (there is no checked-out source for an already-pushed
# image tag, only the tag itself), so an authoritative "does version V's
# migration head match the deployed schema" check is impossible here. What
# IS possible, and what this does: build observer-cloud from the CURRENT
# working tree and run its schema-check against the deployed DSN, printing
# that as an explicitly-labeled deployed-vs-current-HEAD verdict — a
# directional signal, not a verdict about V itself. rc=3 (this tree's
# embedded migration head is BEHIND the deployed schema) is the shape a
# rollback usually produces on purpose (rolling back to an older version
# while the DB already carries migrations from the newer one it is replacing)
# — so rather than silently proceeding, it requires an explicit --yes rather
# than blocking outright: an operator who has not thought about schema
# compatibility must actively confirm, but a genuine emergency rollback is
# never wedged behind a hard refusal with no override. There is no
# --allow-schema-ahead here (forward roll's rc=2 override) and none should be
# added: rc=3 has no bypass on the FORWARD path either (pre_roll_gate's case
# 3 is an unconditional die) — --yes is a DIFFERENT, rollback-specific
# acknowledgment, not a relaxation of that forward invariant.
rollback_schema_check() { # rollback_schema_check <auto_yes: 0|1>
    local auto_yes="$1"
    echo "== rollback schema check (informational — against CURRENT HEAD, not $V's own source) =="

    local dsn
    dsn=$(resolve_pg_dsn)
    if [ -z "$dsn" ]; then
        note "rollback schema check SKIPPED — no deployed-DB DSN available (SBCI_PG_DSN or SBCI_PG_DSN_KV_NAME+SBCI_PG_DSN_KV_SECRET)."
        note "  Proceeding without a schema verdict — this is a KNOWN gap (the rollback target's own"
        note "  source is not available to build from), not a check that ran clean."
        return 0
    fi

    local bin rc=0
    bin=$(mktemp)
    if ! go build -o "$bin" ./cmd/observer-cloud; then
        rm -f "$bin"
        die "rollback schema check: go build (against CURRENT HEAD, for schema-check) failed"
    fi
    SBCI_PG_DSN="$dsn" "$bin" schema-check || rc=$?
    rm -f "$bin"

    case "$rc" in
        0) note "rollback schema check: OK — deployed schema matches CURRENT HEAD's embedded migration head (informational only; not a check of $V itself)" ;;
        2) note "rollback schema check: CURRENT HEAD's embedded migration head is AHEAD of the deployed schema (informational; not necessarily true of $V)" ;;
        3)
            note "rollback schema check: CURRENT HEAD's embedded migration head is BEHIND the deployed schema —"
            note "  the usual shape of a rollback (the DB already carries migrations from the newer version"
            note "  $V is replacing). This does NOT verify $V's own compatibility with the deployed schema."
            if [ "$auto_yes" = "1" ]; then
                note "  proceeding (--yes)"
            else
                die "rollback schema check: refused without --yes (rc=3 — see above). Re-run with --yes to confirm you have reviewed this."
            fi
            ;;
        *)
            note "rollback schema check: observer-cloud schema-check exited $rc (unexpected — check the DSN and connectivity); proceeding (informational check only, never blocks a rollback except rc=3)"
            ;;
    esac
}

roll_apps() { # roll_apps <version>
    local v="$1"
    echo "== rolling $API_APP -> $REG/$API_APP:$v (env=$SBCI_ENV, rg=$RG) =="
    az containerapp update -g "$RG" -n "$API_APP" \
        --image "$REG/$API_APP:$v" -o none
    echo "== rolling $WORKER_APP -> $REG/$WORKER_APP:$v =="
    az containerapp update -g "$RG" -n "$WORKER_APP" \
        --image "$REG/$WORKER_APP:$v" -o none
}

verify() {
    echo "== verify live ($PUBLIC_HOST) =="
    local ok=0 i code
    for i in $(seq 1 12); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$PORTAL_URL/" 2>/dev/null || true)
        if [ "$code" = "200" ]; then ok=1; break; fi
        echo "  portal try $i: HTTP ${code:-000} (waiting for revision)"; sleep 10
    done
    [ "$ok" = 1 ] || die "portal did not reach 200 (check: az containerapp revision list -g $RG -n $API_APP -o table)"
    local ncode
    ncode=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$NONCE_URL" 2>/dev/null || true)
    echo "  portal -> 200 ; /v1/auth/nonce -> ${ncode:-000}"
    echo "  active revisions:"
    az containerapp revision list -g "$RG" -n "$API_APP" \
        --query "[?properties.active].{rev:name,image:properties.template.containers[0].image,healthy:properties.healthState,traffic:properties.trafficWeight}" \
        -o table 2>/dev/null || true
}

case "${1:-}" in
rollback)
    V="${2:?usage: roll-cloud.sh rollback <version> [--yes]}"
    shift 2 || true
    ROLLBACK_YES=0
    for arg in "$@"; do
        case "$arg" in
            --yes) ROLLBACK_YES=1 ;;
            *) die "unknown flag '$arg' (usage: roll-cloud.sh rollback <version> [--yes])" ;;
        esac
    done
    echo "== ROLLBACK cloud ($SBCI_ENV) to $V =="
    az acr repository show-tags -n "$ACR" --repository "$API_APP" -o tsv 2>/dev/null | grep -qx "$V" \
        || die "tag $V not found in $REG/$API_APP — cannot roll back to a non-existent image"
    # No FULL pre-roll gate on rollback: the image already ran successfully
    # once, and re-running go build/vet against whatever the CURRENT working
    # tree happens to be would be checking the wrong thing (the rollback
    # target is the OLD, already-pushed image, not this tree). The schema
    # check is a narrower, informational exception to that rule (P3-g) — see
    # rollback_schema_check.
    rollback_schema_check "$ROLLBACK_YES"
    roll_apps "$V"
    verify
    ;;
"")
    die "usage: roll-cloud.sh <version> [--skip-build] [--allow-schema-ahead] | rollback <version> [--yes]  (SBCI_ENV=staging|prod)"
    ;;
*)
    V="$1"; shift
    SKIP_BUILD=""
    ALLOW_SCHEMA_AHEAD=0
    for arg in "$@"; do
        case "$arg" in
            --skip-build) SKIP_BUILD="1" ;;
            --allow-schema-ahead) ALLOW_SCHEMA_AHEAD=1 ;;
            *) die "unknown flag '$arg' (usage: roll-cloud.sh <version> [--skip-build] [--allow-schema-ahead])" ;;
        esac
    done

    pre_roll_gate "$ALLOW_SCHEMA_AHEAD"

    if [ -z "$SKIP_BUILD" ]; then
        HEAD=$(git rev-parse --short HEAD)
        WORK=$(mktemp -d)
        trap 'rm -rf "$WORK"' EXIT
        echo "== building $API_APP/$WORKER_APP:$V from clean HEAD ($HEAD) =="
        git archive HEAD | tar -x -C "$WORK"
        [ -f "$WORK/Dockerfile.observer-cloud" ] || die "Dockerfile.observer-cloud missing from HEAD archive"
        ( cd "$WORK" && az acr build -r "$ACR" -f Dockerfile.observer-cloud \
            -t "$API_APP:$V" -t "$WORKER_APP:$V" . )
    else
        echo "== --skip-build: rolling already-pushed :$V =="
    fi
    roll_apps "$V"
    verify
    ;;
esac
echo "== cloud roll ($SBCI_ENV) to ${V:-?} complete =="
