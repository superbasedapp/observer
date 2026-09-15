#!/usr/bin/env bash
# cloudintel-azure.sh — az-CLI-based provisioning for the Cloud Intelligence
# service substrate (arc-2 CI-P3a + the production wave, gap 4.1/4.5). Contract
# of record:
#   docs/plans/cloud-intelligence-azure-substrate-contract-2026-08-30.md
#
# SBCI_ENV selects the estate: "staging" (default, byte-identical to every
# prior behaviour of this script) or "prod" (separate RG, eastus2, 35-day
# geo-redundant PITR, VNet+NAT egress lockdown, always-warm api replica — see
# the SBCI_ENV block below and docs/cloud-intelligence-staging-launch-runbook.md §14).
#
#   scripts/cloudintel/cloudintel-azure.sh plan                print resolved names/region/SKUs, NO az calls
#   scripts/cloudintel/cloudintel-azure.sh up                  idempotent create-or-skip
#   scripts/cloudintel/cloudintel-azure.sh db-bootstrap        sbci_svc login role + DSN rotate
#   scripts/cloudintel/cloudintel-azure.sh status               read-only show/list
#   scripts/cloudintel/cloudintel-azure.sh edge-check           dual-host public-vs-origin boundary probes
#   scripts/cloudintel/cloudintel-azure.sh patch-worker-scale   fix an EXISTING worker's degenerate KEDA rule (gap 4.4)
#   scripts/cloudintel/cloudintel-azure.sh down                 delete the RG (typed confirm)
#
# To UPDATE the image after a code change (roll sbci-api + sbci-worker onto a
# new tag), use scripts/roll-cloud.sh — this script provisions, it does not
# roll. Full lifecycle: docs/hosted-surfaces-runbook.md.
#
# The estate (RG defaults to superbased-cloudintel-staging-rg or
# superbased-cloudintel-prod-rg per SBCI_ENV; region eastus2):
#   sbci-api      Container Apps app, external HTTPS ingress, the ONLY public
#                 ingress in the estate; serves /v1/* + the embedded webcloud/
#                 portal (cmd/observer-cloud `serve`). Application routes are
#                 reachable through the Cloudflare authenticated proxy hop;
#                 the raw ACA FQDN is not a supported public origin. Always at
#                 least 1 replica warm (gap 4.8 — a cold-scaled public API
#                 404s instead of cold-starting, see runbook §11).
#   sbci-worker   Container Apps app, NO ingress, fixed 1/1 replicas, NO KEDA
#                 scale rule (gap 4.4 — a pg-mode worker long-polls Postgres,
#                 it doesn't scale on Azure Storage Queue depth); NO Foundry
#                 credential provisioned until post-approval (cmd/observer-cloud `worker`)
#   Postgres      Flexible Server; staging = burstable, 7-day PITR, public
#                 access (AllowAzureServices firewall rule); prod = general
#                 purpose, 35-day geo-redundant PITR, VNet-integrated private
#                 access (gap 4.1) — sslmode=require either way
#   Storage       one account: queues `analysis-jobs` + `analysis-jobs-dead`,
#                 blob container `evidence` (soft-delete DISABLED, 24h
#                 lifecycle-management delete rule as the last-resort backstop
#                 behind the app's own 1h sweeper)
#   Key Vault     evidence wrap key, Postgres admin password, (Foundry key
#                 lands here post-approval only, never provisioned by `up`)
#   Foundry       one Cognitive Services (AIServices) account (NON-PRODUCTION
#                 label on staging, PRODUCTION on prod — cosmetic; what makes
#                 it actually production is the Modified Abuse Monitoring
#                 approval + real ContentLogging attestation, gap 5.1) + a
#                 `luna` Global Standard deployment placeholder
#   2 identities  sbci-api, sbci-worker (user-assigned managed identities,
#                 least-privilege role assignments per contract §2, incl. the
#                 custom "Cloudintel Canary Reader" role — see
#                 canary-reader-role.json)
#   Network       prod only (gap 4.1): one VNet, a Container-Apps-delegated
#                 subnet, a Postgres-delegated subnet, and a NAT Gateway on
#                 the Container Apps subnet for sbci-worker's egress lockdown.
#
# ── SAFETY GATES (read before running) ──────────────────────────────────
#
#   DRY_RUN defaults to 1. Every state-changing az call (and, in `status`,
#   every read-only az call too) goes through the run()/exists()/capture()/
#   show() wrappers below, which print the exact `az ...` invocation and
#   do NOT execute it while DRY_RUN=1. A fresh `up` or `status` invocation
#   with NO environment set prints a complete, coherent resource plan and
#   touches nothing.
#
#   DRY_RUN only turns off when CLOUDINTEL_APPLY=1 is set (and even then,
#   an explicit DRY_RUN=1 in the environment wins — belt and suspenders).
#   Setting DRY_RUN=0 alone, without CLOUDINTEL_APPLY=1, does NOT enable
#   execution. This double-gate is deliberate: it is the one thing standing
#   between an accidental `bash cloudintel-azure.sh up` and a live Azure
#   apply.
#
#   `down` additionally requires the operator to type the resource group's
#   exact name at an interactive prompt before anything is deleted — the
#   script never passes -y/--yes on its own initiative.
#
#   SBCI_PG_EXEC (db-bootstrap only) selects how the admin SQL reaches
#   Postgres: "local" (default, unchanged) from this machine, or "acajob"
#   through an in-VNet Container Apps Job - required for a production
#   Postgres server with no public endpoint. See README "Production: in-VNet
#   admin SQL (SBCI_PG_EXEC=acajob)".
#
# ── WSL / az invocation ──────────────────────────────────────────────────
#
#   Mirrors scripts/demo-azure.sh / scripts/demo-node.sh: if a native `az`
#   binary is on PATH, invocations run directly; otherwise (Windows-only az
#   on this box, as in the existing demo estate) calls fall back to the
#   Windows cmd.exe interop channel, retried across interop flakes, with
#   CRLF stripped from every captured value (`tr -d '\r'`) since az emits
#   CRLF line endings under `--output tsv` through that path.
#
#   The apply-mode (CLOUDINTEL_APPLY=1) path is authored to the documented
#   az CLI syntax but has NOT been exercised against live Azure — this
#   script is written under an author-only constraint (no credentials, and
#   CLOUDINTEL_APPLY must never be set in this lane). Treat first real `up`
#   as a rehearsal, not a proven path.
#
# ── Operator prerequisites (not automated here) ─────────────────────────
#
#   - An identity with Owner (or Contributor + User Access Administrator)
#     at the subscription or RG scope — role assignments and the custom
#     role definition need that.
#   - The sbci-api / sbci-worker container images already pushed to $ACR
#     (this script deploys existing tags; it does not build or push images).
#     BOTH tags are the SAME image, built from Dockerfile.observer-cloud at the
#     repo root; the subcommand is selected per-app via --args (sbci-api ->
#     `serve`, sbci-worker -> `worker`). Build + push once, tagging both:
#       az acr build -r <acr> -f Dockerfile.observer-cloud \
#         -t sbci-api:latest -t sbci-worker:latest .
#     (az acr build submits the context + builds+pushes server-side; run it
#     from a clean tree so only committed state is built.)
#   - See README.md in this directory for the full list of manual
#     post-`up` steps (Postgres login role, real Luna model IDs, Foundry
#     credential flip, EA/MCA + Modified Abuse Monitoring, DNS/Cloudflare
#     Worker route and secret).

set -euo pipefail

# ── SBCI_ENV: staging (default) | prod ───────────────────────────────────
#
#   Every default below is env-parameterized off SBCI_ENV so this ONE script
#   provisions both estates (gap 4.1/4.5). The default is "staging" and every
#   staging-shape default stays byte-identical to before this env split —
#   only `SBCI_ENV=prod` picks the production RG/region/SKUs/network posture.
#   Any single default can still be overridden individually, same as before
#   (e.g. RG=my-custom-rg overrides the env-derived default).
SBCI_ENV="${SBCI_ENV:-staging}"
case "$SBCI_ENV" in
    staging | prod) ;;
    *)
        echo "cloudintel-azure.sh: SBCI_ENV must be 'staging' or 'prod' (got '$SBCI_ENV')" >&2
        exit 2
        ;;
esac
SBCI_ENV_IS_PROD=0
[ "$SBCI_ENV" = "prod" ] && SBCI_ENV_IS_PROD=1

# ── Config (env-overridable) ─────────────────────────────────────────────

if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
    _DEFAULT_RG="superbased-cloudintel-prod-rg"
    _DEFAULT_FOUNDRY_NAME="sbci-prod-foundry"
    _DEFAULT_KV_NAME="sbci-prod-kv"
    _DEFAULT_STORAGE_ACCOUNT="sbciprodstor"
    _DEFAULT_PG_SERVER="sbci-prod-pg"
    _DEFAULT_CAE_NAME="sbci-prod-cae"
    _DEFAULT_LA_NAME="sbci-prod-logs"
    _DEFAULT_PG_TIER="GeneralPurpose"
    _DEFAULT_PG_SKU="Standard_D2ds_v4"
    _DEFAULT_PG_BACKUP_RETENTION_DAYS=35
    _DEFAULT_PG_GEO_REDUNDANT_BACKUP="Enabled"
    _DEFAULT_API_MIN_REPLICAS=1
    _DEFAULT_FOUNDRY_LABEL="PRODUCTION"
else
    _DEFAULT_RG="superbased-cloudintel-staging-rg"
    _DEFAULT_FOUNDRY_NAME="sbci-staging-foundry-nonprod"
    _DEFAULT_KV_NAME="sbci-staging-kv"
    _DEFAULT_STORAGE_ACCOUNT="sbcistagingstor"
    _DEFAULT_PG_SERVER="sbci-staging-pg"
    _DEFAULT_CAE_NAME="sbci-staging-cae"
    _DEFAULT_LA_NAME="sbci-staging-logs"
    _DEFAULT_PG_TIER="Burstable"
    _DEFAULT_PG_SKU="Standard_B1ms"
    _DEFAULT_PG_BACKUP_RETENTION_DAYS=7
    _DEFAULT_PG_GEO_REDUNDANT_BACKUP="Disabled"
    _DEFAULT_API_MIN_REPLICAS=1
    _DEFAULT_FOUNDRY_LABEL="NON-PRODUCTION"
fi

RG="${RG:-$_DEFAULT_RG}"
# eastus is capacity-restricted for Postgres Flexible Server on the estate's
# subscription ("The location is restricted for provisioning of flexible
# servers" — runbook §2, discovered on the first staging apply); eastus2 is
# the grounded default for BOTH envs, and is also the operator's ruling for
# production (region capacity, not a staging/prod difference).
LOCATION="${LOCATION:-eastus2}"

# Registry convention mirrored from scripts/demo-node.sh. This script does
# NOT build or push images; it deploys whatever tag already exists in ACR.
ACR="${ACR:-sbdemoacr35022.azurecr.io}"
API_IMAGE="${API_IMAGE:-$ACR/sbci-api:latest}"
WORKER_IMAGE="${WORKER_IMAGE:-$ACR/sbci-worker:latest}"

# Globally-unique Azure names (Key Vault / Storage / Postgres / Cognitive
# Services all live in a shared namespace). The defaults below are NOT
# guaranteed unique — confirm/override before a real apply, the same way
# the existing demo estate appends a numeric suffix (…35022). Production
# names deliberately do NOT carry "-nonprod"/"-staging" — see README/runbook
# §14 for the exact suffix an operator should append.
CAE_NAME="${CAE_NAME:-$_DEFAULT_CAE_NAME}"
LA_NAME="${LA_NAME:-$_DEFAULT_LA_NAME}"
KV_NAME="${KV_NAME:-$_DEFAULT_KV_NAME}"
KV_URI="https://${KV_NAME}.vault.azure.net"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-$_DEFAULT_STORAGE_ACCOUNT}"
PG_SERVER="${PG_SERVER:-$_DEFAULT_PG_SERVER}"
FOUNDRY_NAME="${FOUNDRY_NAME:-$_DEFAULT_FOUNDRY_NAME}"
# FOUNDRY_LABEL is cosmetic only (the run()/plan text) — it does NOT change
# what gets provisioned (kind/SKU are the same Cognitive Services AIServices
# resource either way; what makes a Foundry resource "production" is the
# Modified Abuse Monitoring approval + real ContentLogging attestation wired
# in cmd/observer-cloud, gap 5.1 — the IaC script cannot provision that).
FOUNDRY_LABEL="${FOUNDRY_LABEL:-$_DEFAULT_FOUNDRY_LABEL}"

API_IDENTITY_NAME="${API_IDENTITY_NAME:-sbci-api}"
WORKER_IDENTITY_NAME="${WORKER_IDENTITY_NAME:-sbci-worker}"

QUEUE_NAME="analysis-jobs"
QUEUE_DEAD_NAME="analysis-jobs-dead"
BLOB_CONTAINER="evidence"

PG_DB="${PG_DB:-sbci}"
PG_ADMIN_USER="${PG_ADMIN_USER:-sbciadmin}"
PG_TIER="${PG_TIER:-$_DEFAULT_PG_TIER}"
PG_SKU="${PG_SKU:-$_DEFAULT_PG_SKU}"
PG_STORAGE_GB="${PG_STORAGE_GB:-32}"
PG_VERSION="${PG_VERSION:-16}"
PG_BACKUP_RETENTION_DAYS="${PG_BACKUP_RETENTION_DAYS:-$_DEFAULT_PG_BACKUP_RETENTION_DAYS}"
# Geo-redundant backup: production-only by default (gap 4.1's 35-day PITR +
# geo-redundant ruling). "Enabled" doubles the backup-storage cost — that is
# the operator's approved production posture, not staging's.
PG_GEO_REDUNDANT_BACKUP="${PG_GEO_REDUNDANT_BACKUP:-$_DEFAULT_PG_GEO_REDUNDANT_BACKUP}"

# SBCI_PG_EXEC selects how db-bootstrap's admin SQL (CREATE ROLE / ALTER ROLE
# / GRANT) reaches Postgres. "local" (default) is the original behaviour:
# local psql, else `az postgres flexible-server execute`, both from the
# operator's own machine over the server's public endpoint. "acajob" runs the
# same SQL inside a Manual-trigger Container Apps Job on the estate's own
# $CAE_NAME, which sits on the VNet-integrated cae-subnet - the only path
# that can reach a production Postgres server with NO public endpoint (see
# README "Production: in-VNet admin SQL"). Staging has a public endpoint and
# never needs "acajob"; it keeps working exactly as before either way.
SBCI_PG_EXEC="${SBCI_PG_EXEC:-local}"
case "$SBCI_PG_EXEC" in
    local | acajob) ;;
    *)
        echo "cloudintel-azure.sh: SBCI_PG_EXEC must be 'local' or 'acajob' (got '$SBCI_PG_EXEC')" >&2
        exit 2
        ;;
esac
PG_ADMIN_JOB_NAME="${PG_ADMIN_JOB_NAME:-${SBCI_ENV}-sbci-pgsql}"
PG_ADMIN_JOB_IMAGE="${PG_ADMIN_JOB_IMAGE:-docker.io/library/postgres:16-alpine}"
PG_ADMIN_JOB_CONTAINER_NAME="${PG_ADMIN_JOB_CONTAINER_NAME:-pgsql}"

# GPT-5.6 Luna identifiers — the operator sets the real values (README).
LUNA_DEPLOYMENT_NAME="luna"
LUNA_MODEL_NAME="${LUNA_MODEL_NAME:-REPLACE_WITH_REAL_LUNA_MODEL_NAME}"
LUNA_MODEL_VERSION="${LUNA_MODEL_VERSION:-REPLACE_WITH_REAL_LUNA_MODEL_VERSION}"
LUNA_MODEL_FORMAT="${LUNA_MODEL_FORMAT:-OpenAI}"
LUNA_SKU="${LUNA_SKU:-GlobalStandard}"
LUNA_CAPACITY="${LUNA_CAPACITY:-1}"

# Matches contract §1 DNS row. Both public hostnames must be served by the same
# Cloudflare Worker proxy described in README; the raw ACA ingress FQDN is an
# origin only and must never be a public DNS target. The API's edge-auth secret
# is provisioned below, while the matching Worker secret is operator-managed.
PUBLIC_API_HOST="${PUBLIC_API_HOST:-cloud.superbased.app}"
# Single-host by default: staging serves the portal on the API host (the
# deployed SBCI_PORTAL_BASE_URL equals SBCI_EXTERNAL_BASE_URL). A two-host
# deployment sets PUBLIC_PORTAL_HOST=app.superbased.app explicitly.
PUBLIC_PORTAL_HOST="${PUBLIC_PORTAL_HOST:-${PUBLIC_API_HOST}}"
EXTERNAL_BASE_URL="${EXTERNAL_BASE_URL:-https://${PUBLIC_API_HOST}}"
PORTAL_BASE_URL="${PORTAL_BASE_URL:-https://${PUBLIC_PORTAL_HOST}}"

# Authenticated Cloudflare -> ACA proxy-hop contract (W6e / E4). The value is
# generated once and kept in Key Vault; it is injected into the API through an
# ACA secret reference. The matching value is installed in the Cloudflare
# Worker with `wrangler secret put` by the operator (never in this repository).
# Keep the header and env names in lock-step with the API implementation.
EDGE_KV_SECRET_NAME="sbci-edge-shared-secret"
EDGE_ACA_SECRET_NAME="edge-shared-secret"
EDGE_ENV_NAME="SBCI_EDGE_SHARED_SECRET"
EDGE_HEADER_NAME="X-SBCI-Edge-Auth"
EDGE_HOST_HEADER_NAME="X-SBCI-Edge-Host"
EDGE_CLIENT_IP_HEADER_NAME="X-SBCI-Client-IP"

API_TARGET_PORT="${API_TARGET_PORT:-8090}"
# gap 4.8: minReplicas>=1 baked in for BOTH envs (a public-ingress API that
# 404s on cold-start is worse than one always-warm replica of cost — staging
# hit exactly this on 2026-08-31, runbook §11). Was previously applied "after
# the fact" via a manual `containerapp update`; now it's the default.
API_MIN_REPLICAS="${API_MIN_REPLICAS:-$_DEFAULT_API_MIN_REPLICAS}"
API_MAX_REPLICAS="${API_MAX_REPLICAS:-3}"
# gap 4.4: the worker's KEDA azure-queue scale rule was degenerate (queue mode
# is provisioned as infrastructure but SBCI_QUEUE_MODE only implements "pg"
# today, so the rule's type/metadata/auth never resolved). A no-ingress
# pg-mode worker doesn't scale on queue depth at all — it long-polls Postgres
# — so the correct shape is min=max=1 and NO scale rule whatsoever (see
# ensure_containerapp_worker below and the patch-worker-scale verb for an
# ALREADY-provisioned app).
WORKER_MIN_REPLICAS="${WORKER_MIN_REPLICAS:-1}"
WORKER_MAX_REPLICAS="${WORKER_MAX_REPLICAS:-1}"

KV_KEY_TYPE="${KV_KEY_TYPE:-RSA}"
KV_KEY_SIZE="${KV_KEY_SIZE:-3072}"

# Custom role DEFINITIONS are subscription-scoped (not RG-scoped), so their
# display name carries $SBCI_ENV rather than a hardcoded "(staging)" — two
# envs in the same subscription get two distinct role definitions, each
# assigned only at its own env's resource scope below. Default SBCI_ENV=staging
# keeps every name byte-identical to before this split.
CANARY_ROLE_NAME="Cloudintel Canary Reader (${SBCI_ENV})"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANARY_ROLE_TEMPLATE="${SCRIPT_DIR}/canary-reader-role.json"

# Custom least-privilege data-action roles (plan §6 CI-P6 IaC #3/#4). These
# SPLIT the coarse built-in roles the script used to assign: Key Vault Crypto
# User (bundles wrap+unwrap+encrypt+decrypt) and Storage Blob Data Contributor
# (read+write+delete+add+...). Each role name maps to a JSON definition beside
# this script (rendered with the live subscription id, create-or-updated, then
# assigned at a narrow scope). Data-action custom roles can lag RBAC
# propagation ~5min on first assignment — see README.
KV_WRAP_ROLE_NAME="Cloudintel KV Crypto Wrap (${SBCI_ENV})"
KV_WRAP_ROLE_TEMPLATE="${SCRIPT_DIR}/kv-crypto-wrap-role.json"
KV_UNWRAP_ROLE_NAME="Cloudintel KV Crypto Unwrap (${SBCI_ENV})"
KV_UNWRAP_ROLE_TEMPLATE="${SCRIPT_DIR}/kv-crypto-unwrap-role.json"
BLOB_API_ROLE_NAME="Cloudintel Evidence Blob Writer (${SBCI_ENV})"
BLOB_API_ROLE_TEMPLATE="${SCRIPT_DIR}/blob-evidence-api-role.json"
BLOB_WORKER_ROLE_NAME="Cloudintel Evidence Blob Reader-Deleter (${SBCI_ENV})"
BLOB_WORKER_ROLE_TEMPLATE="${SCRIPT_DIR}/blob-evidence-worker-role.json"

# ── Network lockdown (production only — gap 4.1) ─────────────────────────
#
#   Staging keeps the existing public-access-firewall Postgres posture and an
#   un-VNet-integrated Container Apps environment (contract §3's documented
#   staging-only shortcut). Production gets a VNet with two delegated
#   subnets — one for the Container Apps environment, one for Postgres
#   Flexible Server's private-access VNet integration — plus a NAT Gateway
#   associated with the Container Apps subnet so sbci-worker's outbound calls
#   (Foundry, ARM, Key Vault, Storage) leave through one stable, allow-
#   listable address instead of the Consumption tier's shared, unpredictable
#   egress pool. These vars are read only when SBCI_ENV=prod.
VNET_NAME="${VNET_NAME:-sbci-${SBCI_ENV}-vnet}"
VNET_ADDRESS_PREFIX="${VNET_ADDRESS_PREFIX:-10.60.0.0/16}"
CAE_SUBNET_NAME="${CAE_SUBNET_NAME:-cae-subnet}"
CAE_SUBNET_PREFIX="${CAE_SUBNET_PREFIX:-10.60.0.0/23}"
PG_SUBNET_NAME="${PG_SUBNET_NAME:-pg-subnet}"
PG_SUBNET_PREFIX="${PG_SUBNET_PREFIX:-10.60.2.0/24}"
NAT_GATEWAY_NAME="${NAT_GATEWAY_NAME:-sbci-${SBCI_ENV}-natgw}"
NAT_PUBLIC_IP_NAME="${NAT_PUBLIC_IP_NAME:-sbci-${SBCI_ENV}-natgw-ip}"

# ── DRY_RUN / CLOUDINTEL_APPLY double gate ───────────────────────────────

CLOUDINTEL_APPLY="${CLOUDINTEL_APPLY:-0}"
if [ "$CLOUDINTEL_APPLY" = "1" ]; then
    DRY_RUN="${DRY_RUN:-0}"
else
    DRY_RUN=1
fi

# ── Secret redaction (house pattern from scripts/demo-node.sh) ──────────

declare -a REDACT_NAMES=()
declare -a REDACT_VALUES=()

register_secret() { # register_secret <name> <value>
    REDACT_NAMES+=("$1")
    REDACT_VALUES+=("$2")
}

redact() { # redact <text> -> text with every registered secret value replaced
    local text="$1" i
    for i in "${!REDACT_NAMES[@]}"; do
        local v="${REDACT_VALUES[$i]}"
        [ -n "$v" ] || continue
        text="${text//$v/[REDACTED:${REDACT_NAMES[$i]} len=${#v}]}"
    done
    printf '%s' "$text"
}

# ── Low-level az invocation (native az, else Windows cmd.exe interop) ───

quote_args() { # quote_args <args...> -> a single display-quoted string
    local out="" a
    for a in "$@"; do
        out="$out $(printf '%q' "$a")"
    done
    printf '%s' "${out# }"
}

# azexec_raw <az args...> — state-changing call, retried 3x. APPLY-MODE ONLY
# (never reached while DRY_RUN=1).
azexec_raw() {
    local i out rc
    for i in 1 2 3; do
        if command -v az >/dev/null 2>&1; then
            out=$(az "$@" 2>&1); rc=$?
        else
            out=$( (cd /mnt/c 2>/dev/null && cmd.exe /c "az $(quote_args "$@")" 2>&1) | tr -d '\r' ); rc=$?
        fi
        # The WSL/cmd.exe interop does not reliably propagate az's non-zero exit
        # code, so an az `ERROR:` line in the OUTPUT is treated as failure even
        # when rc==0. Without this, run() prints "done" on a failed call and
        # `set -e` never fires — the class of bug that made the first staging
        # apply plow straight through failed KV-role, Key Vault data-plane, and
        # Postgres steps instead of stopping.
        if [ "$rc" = "0" ] && ! printf '%s\n' "$out" | grep -qE '^ERROR:'; then
            printf '%s\n' "$out"; return 0
        fi
        [ "$rc" = "0" ] && rc=1
        sleep 3
    done
    echo "azexec: FAILED after 3 tries: $(redact "$out")" >&2
    return "${rc:-1}"
}

# azquery_raw <az args...> — read-only call, no retry (used by exists/capture/show).
azquery_raw() {
    if command -v az >/dev/null 2>&1; then
        az "$@" 2>/dev/null | tr -d '\r'
        return "${PIPESTATUS[0]}"
    fi
    (cd /mnt/c 2>/dev/null && cmd.exe /c "az $(quote_args "$@")" 2>/dev/null) | tr -d '\r'
    return "${PIPESTATUS[0]}"
}

# ── DRY_RUN-aware mid-level wrappers — every call site in this file goes
# through one of these four, so DRY_RUN=1 never reaches azexec_raw/azquery_raw ──

run() { # run <label> <az args...> — state-changing
    local label="$1"; shift
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  %s\n          az %s\n' "$label" "$(quote_args "$@")"
        return 0
    fi
    printf '  [apply] %s\n' "$label"
    if azexec_raw "$@" >/dev/null; then
        printf '          done\n'
    else
        printf '          FAILED\n' >&2
        return 1
    fi
}

exists() { # exists <label> <az args...> — 0 if found (skip create), 1 if not
    local label="$1"; shift
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [check] %s\n          az %s\n          (dry-run: treated as NOT FOUND, so the create step below is included in the plan)\n' \
            "$label" "$(quote_args "$@")"
        return 1
    fi
    if azquery_raw "$@" >/dev/null; then
        printf '  [check] %s — found, skipping create\n' "$label"
        return 0
    fi
    printf '  [check] %s — not found\n' "$label"
    return 1
}

capture() { # capture <VARNAME> <label> <az args...> — assigns VARNAME
    local __var="$1" label="$2"; shift 2
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  capture %s\n          az %s\n' "$label" "$(quote_args "$@")"
        printf -v "$__var" '%s' "<dry-run:${label}>"
        return 0
    fi
    local val
    if val=$(azquery_raw "$@"); then
        printf -v "$__var" '%s' "$val"
        return 0
    fi
    echo "capture: failed to obtain $label" >&2
    return 1
}

show() { # show <label> <az args...> — status-verb display line
    local label="$1"; shift
    if [ "$DRY_RUN" = "1" ]; then
        printf '  %-30s [dry-run] az %s\n' "${label}:" "$(quote_args "$@")"
        return 0
    fi
    local val
    if val=$(azquery_raw "$@"); then
        printf '  %-30s %s\n' "${label}:" "${val:-<empty>}"
    else
        printf '  %-30s <not found>\n' "${label}:"
    fi
}

gen_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 33 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 32
    else
        head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32
    fi
}

# gen_edge_secret emits exactly 32 random bytes as 64 hexadecimal characters.
# Hex avoids shell/URL/header quoting surprises and makes accidental trailing
# whitespace easy to reject during the Key Vault read-back below. The value is
# never printed; callers must register it with register_secret before any
# command that could include it in diagnostics.
gen_edge_secret() {
    local value
    if command -v openssl >/dev/null 2>&1 && value=$(openssl rand -hex 32 2>/dev/null); then
        printf '%s' "$value"
        return 0
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n\r'
}

# ── Foundational resources ───────────────────────────────────────────────

ensure_resource_group() {
    if exists "resource group $RG" group show -n "$RG"; then return 0; fi
    run "create resource group $RG ($LOCATION)" group create -n "$RG" -l "$LOCATION"
}

capture_subscription_id() {
    capture SUBSCRIPTION_ID "subscription id" account show --query id -o tsv
}

ensure_log_analytics() {
    if ! exists "log analytics workspace $LA_NAME" \
        monitor log-analytics workspace show -g "$RG" -n "$LA_NAME"; then
        run "create log analytics workspace $LA_NAME" \
            monitor log-analytics workspace create -g "$RG" -n "$LA_NAME" -l "$LOCATION"
    fi
    capture LA_ID "log analytics customerId" \
        monitor log-analytics workspace show -g "$RG" -n "$LA_NAME" --query customerId -o tsv
    capture LA_KEY "log analytics primarySharedKey" \
        monitor log-analytics workspace get-shared-keys -g "$RG" -n "$LA_NAME" --query primarySharedKey -o tsv
    register_secret "log-analytics-key" "$LA_KEY"
}

ensure_container_apps_env() {
    if exists "container apps environment $CAE_NAME" \
        containerapp env show -g "$RG" -n "$CAE_NAME"; then
        return 0
    fi
    if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
        run "create container apps environment $CAE_NAME (VNet-integrated, subnet $CAE_SUBNET_NAME — gap 4.1)" \
            containerapp env create -g "$RG" -n "$CAE_NAME" -l "$LOCATION" \
            --logs-workspace-id "$LA_ID" --logs-workspace-key "$LA_KEY" \
            --infrastructure-subnet-resource-id "$CAE_SUBNET_ID"
    else
        run "create container apps environment $CAE_NAME" \
            containerapp env create -g "$RG" -n "$CAE_NAME" -l "$LOCATION" \
            --logs-workspace-id "$LA_ID" --logs-workspace-key "$LA_KEY"
    fi
}

# ensure_prod_network provisions the VNet + two delegated subnets + NAT
# Gateway used to lock down production egress (gap 4.1). Called ONLY when
# SBCI_ENV=prod, before ensure_container_apps_env and ensure_postgres_server
# (both consume its captured subnet ids/names). Staging is unaffected — it
# keeps the existing public-access-firewall Postgres posture and an
# un-VNet-integrated Container Apps environment.
ensure_prod_network() {
    if ! exists "virtual network $VNET_NAME" \
        network vnet show -g "$RG" -n "$VNET_NAME"; then
        run "create virtual network $VNET_NAME ($VNET_ADDRESS_PREFIX)" \
            network vnet create -g "$RG" -n "$VNET_NAME" -l "$LOCATION" \
            --address-prefix "$VNET_ADDRESS_PREFIX"
    fi
    if ! exists "subnet $CAE_SUBNET_NAME (Container Apps environment, delegated)" \
        network vnet subnet show -g "$RG" --vnet-name "$VNET_NAME" -n "$CAE_SUBNET_NAME"; then
        run "create + delegate subnet $CAE_SUBNET_NAME ($CAE_SUBNET_PREFIX) to Microsoft.App/environments" \
            network vnet subnet create -g "$RG" --vnet-name "$VNET_NAME" -n "$CAE_SUBNET_NAME" \
            --address-prefixes "$CAE_SUBNET_PREFIX" \
            --delegations Microsoft.App/environments
    fi
    if ! exists "subnet $PG_SUBNET_NAME (Postgres Flexible Server, delegated)" \
        network vnet subnet show -g "$RG" --vnet-name "$VNET_NAME" -n "$PG_SUBNET_NAME"; then
        run "create + delegate subnet $PG_SUBNET_NAME ($PG_SUBNET_PREFIX) to Microsoft.DBforPostgreSQL/flexibleServers" \
            network vnet subnet create -g "$RG" --vnet-name "$VNET_NAME" -n "$PG_SUBNET_NAME" \
            --address-prefixes "$PG_SUBNET_PREFIX" \
            --delegations Microsoft.DBforPostgreSQL/flexibleServers
    fi
    if ! exists "public IP $NAT_PUBLIC_IP_NAME (NAT gateway egress address)" \
        network public-ip show -g "$RG" -n "$NAT_PUBLIC_IP_NAME"; then
        run "create public IP $NAT_PUBLIC_IP_NAME (Standard SKU, static)" \
            network public-ip create -g "$RG" -n "$NAT_PUBLIC_IP_NAME" -l "$LOCATION" \
            --sku Standard --allocation-method Static
    fi
    if ! exists "NAT gateway $NAT_GATEWAY_NAME" \
        network nat gateway show -g "$RG" -n "$NAT_GATEWAY_NAME"; then
        run "create NAT gateway $NAT_GATEWAY_NAME (worker egress lockdown)" \
            network nat gateway create -g "$RG" -n "$NAT_GATEWAY_NAME" -l "$LOCATION" \
            --public-ip-addresses "$NAT_PUBLIC_IP_NAME"
    fi
    # The Container Apps environment's ONE infra subnet carries both apps
    # (Consumption-tier CAE has no per-app subnet split) — the NAT gateway
    # therefore governs sbci-worker's egress (the thing this is for) and
    # sbci-api's egress identically. sbci-api's INGRESS stays on the CAE's own
    # external ingress per the substrate contract (§3) — this NAT gateway is an
    # EGRESS control, not a replacement for the Cloudflare Worker ingress hop.
    run "associate NAT gateway $NAT_GATEWAY_NAME with subnet $CAE_SUBNET_NAME" \
        network vnet subnet update -g "$RG" --vnet-name "$VNET_NAME" -n "$CAE_SUBNET_NAME" \
        --nat-gateway "$NAT_GATEWAY_NAME"
    capture CAE_SUBNET_ID "Container Apps subnet resource id" \
        network vnet subnet show -g "$RG" --vnet-name "$VNET_NAME" -n "$CAE_SUBNET_NAME" --query id -o tsv
    capture PG_SUBNET_ID "Postgres delegated subnet resource id" \
        network vnet subnet show -g "$RG" --vnet-name "$VNET_NAME" -n "$PG_SUBNET_NAME" --query id -o tsv
}

# ── Identities ────────────────────────────────────────────────────────────

ensure_identity() { # ensure_identity <name> <VAR-prefix>
    local name="$1" prefix="$2"
    if ! exists "managed identity $name" identity show -g "$RG" -n "$name"; then
        run "create managed identity $name" identity create -g "$RG" -n "$name" -l "$LOCATION"
    fi
    capture "${prefix}_ID" "$name identity resource id" \
        identity show -g "$RG" -n "$name" --query id -o tsv
    capture "${prefix}_PRINCIPAL_ID" "$name identity principalId" \
        identity show -g "$RG" -n "$name" --query principalId -o tsv
    capture "${prefix}_CLIENT_ID" "$name identity clientId" \
        identity show -g "$RG" -n "$name" --query clientId -o tsv
}

# ── Key Vault ─────────────────────────────────────────────────────────────

ensure_keyvault() {
    if ! exists "key vault $KV_NAME" keyvault show -n "$KV_NAME" -g "$RG"; then
        run "create key vault $KV_NAME (RBAC authorization)" \
            keyvault create -n "$KV_NAME" -g "$RG" -l "$LOCATION" \
            --enable-rbac-authorization true
    fi
    capture KV_ID "key vault resource id" keyvault show -n "$KV_NAME" -g "$RG" --query id -o tsv
    KV_URI="https://${KV_NAME}.vault.azure.net"
}

# ensure_edge_shared_secret creates the one-hop authentication secret once and
# reuses it on later idempotent `up` runs. The API receives it only through a
# Key Vault-backed Container Apps secret reference. The Cloudflare Worker copy
# is deliberately NOT automated here: it belongs in the Cloudflare account's
# encrypted secret store and must be supplied by the operator out-of-band (see
# README). A malformed existing value is refused rather than silently wiring a
# value that the Worker and API could interpret differently.
ensure_edge_shared_secret() {
    local secret_name="$EDGE_KV_SECRET_NAME"
    if exists "key vault secret $secret_name (Cloudflare authenticated hop)" \
        keyvault secret show --vault-name "$KV_NAME" --name "$secret_name"; then
        if [ "$DRY_RUN" = "1" ]; then
            EDGE_SHARED_SECRET="<dry-run:existing-edge-secret>"
        else
            EDGE_SHARED_SECRET=$(azquery_raw keyvault secret show \
                --vault-name "$KV_NAME" --name "$secret_name" --query value -o tsv)
            if ! [[ "$EDGE_SHARED_SECRET" =~ ^[[:xdigit:]]{64}$ ]]; then
                echo "ensure_edge_shared_secret: $secret_name is not exactly 64 hexadecimal characters" >&2
                echo "  Refusing to wire a malformed edge secret. Rotate it with the procedure in scripts/cloudintel/README.md." >&2
                return 1
            fi
            register_secret "edge-shared-secret" "$EDGE_SHARED_SECRET"
        fi
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  generate a 32-byte Cloudflare authenticated-hop secret and store it in Key Vault as %s (value REDACTED)\n' \
            "$secret_name"
        printf '          the matching value must be installed separately in the Cloudflare Worker secret store; see README\n'
        EDGE_SHARED_SECRET="<dry-run:generated-edge-secret>"
        return 0
    fi
    EDGE_SHARED_SECRET="$(gen_edge_secret)"
    if ! [[ "$EDGE_SHARED_SECRET" =~ ^[[:xdigit:]]{64}$ ]]; then
        echo "ensure_edge_shared_secret: local random source did not produce 64 hexadecimal characters" >&2
        return 1
    fi
    register_secret "edge-shared-secret" "$EDGE_SHARED_SECRET"
    run "store generated Cloudflare authenticated-hop secret to Key Vault ($secret_name)" \
        keyvault secret set --vault-name "$KV_NAME" --name "$secret_name" --value "$EDGE_SHARED_SECRET"
}

# kv_dataplane_ready — true when the operator can perform a KV data-plane read.
# RBAC data-plane grants can lag several minutes after assignment; this checks
# the OUTPUT for Forbidden/ERROR rather than the exit code (the same interop
# exit-code unreliability azexec_raw compensates for). An empty vault lists no
# secrets and prints nothing ⇒ ready.
kv_dataplane_ready() {
    local out
    if command -v az >/dev/null 2>&1; then
        out=$(az keyvault secret list --vault-name "$KV_NAME" -o tsv 2>&1)
    else
        out=$( (cd /mnt/c 2>/dev/null && cmd.exe /c "az keyvault secret list --vault-name $KV_NAME -o tsv" 2>&1) | tr -d '\r' )
    fi
    ! printf '%s\n' "$out" | grep -qiE 'Forbidden|ERROR:'
}

# ensure_operator_kv_access — grant the OPERATOR running this script Key Vault
# data-plane access, then wait for RBAC propagation. A fresh RBAC-authorization
# vault gives the subscription Owner MANAGEMENT-plane control but NO data-plane
# (keys/secrets) access, so ensure_evidence_wrap_key / ensure_pg_*_secret below
# fail with (Forbidden) without this. Surfaced by the first real staging apply
# (2026-08-31). "Key Vault Administrator" is the OPERATOR's bring-up grant (the
# APPS keep their least-privilege split roles below).
ensure_operator_kv_access() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  grant the signed-in operator "Key Vault Administrator" on %s (data-plane; Owner alone cannot read/write keys or secrets on an RBAC vault)\n' "$KV_NAME"
        printf '          az ad signed-in-user show --query id -o tsv   # operator object id\n'
        printf '          az role assignment create --assignee-object-id <oid> --assignee-principal-type User --role "Key Vault Administrator" --scope %s\n' "$KV_ID"
        printf '  [plan]  then poll a benign KV data-plane read until RBAC propagation completes (up to ~8 min)\n'
        return 0
    fi
    local oid
    oid=$(azquery_raw ad signed-in-user show --query id -o tsv)
    if ! printf '%s' "$oid" | grep -qE '^[0-9a-fA-F-]{36}$'; then
        echo "ensure_operator_kv_access: could not resolve the signed-in operator object id (got: '$oid')" >&2
        return 1
    fi
    run "role assignment: operator -> Key Vault Administrator on $KV_NAME (data-plane bring-up)" \
        role assignment create --assignee-object-id "$oid" --assignee-principal-type User \
        --role "Key Vault Administrator" --scope "$KV_ID"
    printf '  [wait]  KV data-plane RBAC propagation (polling secret list; up to ~8 min)\n'
    local t
    for t in $(seq 1 16); do
        if kv_dataplane_ready; then
            printf '          data-plane ready after ~%ds\n' "$(( (t - 1) * 30 ))"
            return 0
        fi
        sleep 30
    done
    echo "ensure_operator_kv_access: KV data-plane still Forbidden after ~8 min — RBAC propagation may need longer; re-run 'up' to resume." >&2
    return 1
}

ensure_kv_role_assignments() {
    # sbci-api: get secrets (contract §2 "get") + wrapKey ONLY via the custom
    # split role (was the coarse built-in "Key Vault Crypto User", which also
    # granted unwrap/decrypt the API never needs).
    run "role assignment: sbci-api -> Key Vault Secrets User" \
        role assignment create --assignee-object-id "$API_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" --scope "$KV_ID"
    ensure_custom_role "$KV_WRAP_ROLE_NAME" "$KV_WRAP_ROLE_TEMPLATE"
    run "role assignment: sbci-api -> \"$KV_WRAP_ROLE_NAME\" (wrapKey only) on $KV_NAME" \
        role assignment create --assignee-object-id "$API_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "$KV_WRAP_ROLE_NAME" --scope "$KV_ID"

    # sbci-worker: get secrets + unwrapKey ONLY via the custom split role — the
    # worker unwraps the wrapped data key to decrypt evidence, and does no
    # wrapping. This closes the old over-grant (built-in Crypto User bundled
    # both wrap and unwrap for both identities).
    run "role assignment: sbci-worker -> Key Vault Secrets User" \
        role assignment create --assignee-object-id "$WORKER_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "Key Vault Secrets User" --scope "$KV_ID"
    ensure_custom_role "$KV_UNWRAP_ROLE_NAME" "$KV_UNWRAP_ROLE_TEMPLATE"
    run "role assignment: sbci-worker -> \"$KV_UNWRAP_ROLE_NAME\" (unwrapKey only) on $KV_NAME" \
        role assignment create --assignee-object-id "$WORKER_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "$KV_UNWRAP_ROLE_NAME" --scope "$KV_ID"
}

ensure_evidence_wrap_key() {
    if exists "key vault key evidence-wrap-key" \
        keyvault key show --vault-name "$KV_NAME" --name evidence-wrap-key; then
        return 0
    fi
    run "create evidence envelope-encryption wrap key" \
        keyvault key create --vault-name "$KV_NAME" --name evidence-wrap-key \
        --kty "$KV_KEY_TYPE" --size "$KV_KEY_SIZE"
}

ensure_pg_admin_secret() {
    local secret_name="sbci-pg-admin-password"
    if exists "key vault secret $secret_name" \
        keyvault secret show --vault-name "$KV_NAME" --name "$secret_name"; then
        # Reuse the existing password rather than regenerating (idempotent-up
        # must not rotate credentials under a live server).
        if [ "$DRY_RUN" != "1" ]; then
            PG_ADMIN_PASSWORD=$(azquery_raw keyvault secret show --vault-name "$KV_NAME" \
                --name "$secret_name" --query value -o tsv)
            register_secret "pg-admin-password" "$PG_ADMIN_PASSWORD"
        else
            PG_ADMIN_PASSWORD="<dry-run:existing-kv-secret>"
        fi
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  generate a Postgres admin password and store it to Key Vault\n'
        printf '          az keyvault secret set --vault-name %s --name %s --value <REDACTED, 32 random chars>\n' \
            "$KV_NAME" "$secret_name"
        PG_ADMIN_PASSWORD="<dry-run:generated>"
        return 0
    fi
    PG_ADMIN_PASSWORD="$(gen_password)"
    register_secret "pg-admin-password" "$PG_ADMIN_PASSWORD"
    run "store generated Postgres admin password to Key Vault" \
        keyvault secret set --vault-name "$KV_NAME" --name "$secret_name" --value "$PG_ADMIN_PASSWORD"
}

# ── Postgres ──────────────────────────────────────────────────────────────

ensure_postgres_server() {
    if ! exists "postgres flexible server $PG_SERVER" \
        postgres flexible-server show -g "$RG" -n "$PG_SERVER"; then
        if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
            run "create postgres flexible server $PG_SERVER ($PG_TIER $PG_SKU, VNet-integrated subnet $PG_SUBNET_NAME, ${PG_BACKUP_RETENTION_DAYS}d PITR, geo-redundant backup $PG_GEO_REDUNDANT_BACKUP — gap 4.1)" \
                postgres flexible-server create -g "$RG" -n "$PG_SERVER" -l "$LOCATION" \
                --tier "$PG_TIER" --sku-name "$PG_SKU" --storage-size "$PG_STORAGE_GB" \
                --version "$PG_VERSION" --admin-user "$PG_ADMIN_USER" --admin-password "$PG_ADMIN_PASSWORD" \
                --backup-retention "$PG_BACKUP_RETENTION_DAYS" --geo-redundant-backup "$PG_GEO_REDUNDANT_BACKUP" \
                --high-availability Disabled --database-name "$PG_DB" \
                --vnet "$VNET_NAME" --subnet "$PG_SUBNET_NAME" --yes
        else
            run "create postgres flexible server $PG_SERVER ($PG_TIER $PG_SKU, ${PG_BACKUP_RETENTION_DAYS}d PITR)" \
                postgres flexible-server create -g "$RG" -n "$PG_SERVER" -l "$LOCATION" \
                --tier "$PG_TIER" --sku-name "$PG_SKU" --storage-size "$PG_STORAGE_GB" \
                --version "$PG_VERSION" --admin-user "$PG_ADMIN_USER" --admin-password "$PG_ADMIN_PASSWORD" \
                --backup-retention "$PG_BACKUP_RETENTION_DAYS" --high-availability Disabled \
                --database-name "$PG_DB" --yes
        fi
    fi
    if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
        # VNet-integrated (private access) servers have no public firewall rule
        # to create — connectivity is scoped to the delegated $PG_SUBNET_NAME
        # instead (gap 4.1's egress-lockdown ruling).
        printf '  [check] postgres firewall — VNet-integrated via %s; no public AllowAzureServices rule (production)\n' "$PG_SUBNET_NAME"
    else
        # Public access + firewall rule below is the staging posture; contract §3
        # marks VNet+NAT egress lockdown as a production launch-gate item.
        run "allow-Azure-services firewall rule on $PG_SERVER (staging; VNet lockdown is a production launch-gate item)" \
            postgres flexible-server firewall-rule create -g "$RG" -n "$PG_SERVER" \
            --rule-name AllowAzureServices --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0
    fi
    # Azure Flexible Server refuses CREATE EXTENSION for anything not allow-listed in
    # the azure.extensions server parameter. Migration 0014 needs btree_gist; the
    # first production migrate (2026-09-13) failed here because staging had been
    # set by hand (user-override) and this script never covered it. Idempotent.
    run "allow-list btree_gist on $PG_SERVER (azure.extensions server parameter; migration 0014 CREATE EXTENSION btree_gist)" \
        postgres flexible-server parameter set -g "$RG" -s "$PG_SERVER" -n azure.extensions -v BTREE_GIST
    # NOTE (honest limitation, production/VNet-integrated only): a
    # --vnet/--subnet server resolves through a private DNS zone Azure
    # provisions alongside it (by default named after the server, in the same
    # shape as the public FQDN). This script has NOT been run against live
    # Azure with VNet integration (the apply-mode path is author-only per the
    # script header) — verify the actual private DNS zone name at first real
    # prod apply and correct PG_FQDN here if it differs.
    PG_FQDN="${PG_SERVER}.postgres.database.azure.com"
}

ensure_pg_dsn_secret() {
    local secret_name="sbci-pg-dsn"
    if exists "key vault secret $secret_name" \
        keyvault secret show --vault-name "$KV_NAME" --name "$secret_name"; then
        return 0
    fi
    local dsn="postgresql://${PG_ADMIN_USER}:${PG_ADMIN_PASSWORD}@${PG_FQDN}:5432/${PG_DB}?sslmode=require"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  store the admin-credentialed Postgres DSN to Key Vault as %s\n' "$secret_name"
        printf '          az keyvault secret set --vault-name %s --name %s --value <REDACTED, contains admin password>\n' \
            "$KV_NAME" "$secret_name"
        printf '          NOTE: this is a bring-up DSN using the SERVER ADMIN login. Contract §2 wants\n'
        printf '          the app to run as sbci_app via a dedicated login role — see README "manual steps".\n'
        return 0
    fi
    register_secret "pg-dsn" "$dsn"
    run "store Postgres DSN to Key Vault ($secret_name) — admin login, see README for the sbci_app login-role follow-up" \
        keyvault secret set --vault-name "$KV_NAME" --name "$secret_name" --value "$dsn"
}

# ── Storage: account, queues, container, lifecycle, soft-delete ────────────

ensure_storage_account() {
    if ! exists "storage account $STORAGE_ACCOUNT" \
        storage account show -g "$RG" -n "$STORAGE_ACCOUNT"; then
        run "create storage account $STORAGE_ACCOUNT (StorageV2, LRS, TLS1.2, no public blob access)" \
            storage account create -g "$RG" -n "$STORAGE_ACCOUNT" -l "$LOCATION" \
            --kind StorageV2 --sku Standard_LRS --min-tls-version TLS1_2 \
            --allow-blob-public-access false
    fi
    capture STORAGE_ID "storage account resource id" \
        storage account show -g "$RG" -n "$STORAGE_ACCOUNT" --query id -o tsv
}

ensure_storage_queue() { # ensure_storage_queue <name>
    local name="$1"
    if exists "storage queue $name" \
        storage queue exists --account-name "$STORAGE_ACCOUNT" --name "$name" --auth-mode login \
        --query value -o tsv; then
        return 0
    fi
    run "create storage queue $name" \
        storage queue create --account-name "$STORAGE_ACCOUNT" --name "$name" --auth-mode login
}

ensure_blob_container() {
    if exists "blob container $BLOB_CONTAINER" \
        storage container exists --account-name "$STORAGE_ACCOUNT" --name "$BLOB_CONTAINER" \
        --auth-mode login --query exists -o tsv; then
        return 0
    fi
    run "create blob container $BLOB_CONTAINER (no anonymous access)" \
        storage container create --account-name "$STORAGE_ACCOUNT" --name "$BLOB_CONTAINER" \
        --auth-mode login --public-access off
}

ensure_blob_soft_delete_disabled() {
    # Contract §4/§1: blob soft-delete must stay DISABLED on `evidence` so the
    # 24h platform lifecycle rule and the app's 1h sweeper can actually make
    # deletions permanent. This is a service-level (whole-account) toggle in
    # az CLI — there is no per-container soft-delete knob — which is exactly
    # why this account is dedicated to Cloud Intelligence rather than shared.
    run "disable blob + container soft-delete on $STORAGE_ACCOUNT (service-level; account is dedicated to this estate)" \
        storage account blob-service-properties update -g "$RG" -n "$STORAGE_ACCOUNT" \
        --enable-delete-retention false --enable-container-delete-retention false
}

ensure_lifecycle_policy() {
    local policy_file
    policy_file="$(mktemp /tmp/cloudintel-lifecycle.XXXXXX.json)"
    cat >"$policy_file" <<'EOF'
{
  "rules": [
    {
      "enabled": true,
      "name": "evidence-24h-backstop",
      "type": "Lifecycle",
      "definition": {
        "actions": {
          "baseBlob": {
            "delete": { "daysAfterModificationGreaterThan": 1 }
          }
        },
        "filters": {
          "blobTypes": ["blockBlob"],
          "prefixMatch": ["evidence/"]
        }
      }
    }
  ]
}
EOF
    # NOTE (honest limitation): Azure Storage lifecycle-management policies
    # run once per day and only support day-granularity thresholds — there is
    # no az CLI way to express an exact 24h TTL. "daysAfterModificationGreaterThan":1
    # means blobs are swept somewhere between ~24h and ~48h after creation.
    # That's fine per the contract framing (this rule is a LAST-RESORT
    # backstop behind the app's own 1h sweeper, not the authoritative TTL),
    # but it is not a precise 24h SLA and should be understood as such.
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  apply blob lifecycle-management policy (24-48h backstop delete on evidence/*)\n'
        printf '          az storage account management-policy create -g %s --account-name %s --policy @%s\n' \
            "$RG" "$STORAGE_ACCOUNT" "$policy_file"
        printf '          (rendered policy left at %s for inspection)\n' "$policy_file"
        return 0
    fi
    run "apply blob lifecycle-management policy (24-48h backstop delete on evidence/*)" \
        storage account management-policy create -g "$RG" --account-name "$STORAGE_ACCOUNT" \
        --policy "@${policy_file}"
    rm -f "$policy_file"
}

ensure_storage_role_assignments() {
    local queue_scope="${STORAGE_ID}/queueServices/default/queues/${QUEUE_NAME}"
    local queue_dead_scope="${STORAGE_ID}/queueServices/default/queues/${QUEUE_DEAD_NAME}"
    local blob_scope="${STORAGE_ID}/blobServices/default/containers/${BLOB_CONTAINER}"

    run "role assignment: sbci-api -> Storage Queue Data Message Sender on $QUEUE_NAME" \
        role assignment create --assignee-object-id "$API_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "Storage Queue Data Message Sender" --scope "$queue_scope"
    # sbci-api blob access: read+write+delete via the custom split role (was the
    # coarse built-in "Storage Blob Data Contributor", which also carried
    # add/action + move/action + container management the API never needs).
    ensure_custom_role "$BLOB_API_ROLE_NAME" "$BLOB_API_ROLE_TEMPLATE"
    run "role assignment: sbci-api -> \"$BLOB_API_ROLE_NAME\" (read/write/delete) on $BLOB_CONTAINER" \
        role assignment create --assignee-object-id "$API_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "$BLOB_API_ROLE_NAME" --scope "$blob_scope"

    run "role assignment: sbci-worker -> Storage Queue Data Message Processor on $QUEUE_NAME (receive/delete)" \
        role assignment create --assignee-object-id "$WORKER_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "Storage Queue Data Message Processor" --scope "$queue_scope"
    run "role assignment: sbci-worker -> Storage Queue Data Message Sender on $QUEUE_DEAD_NAME (move poison messages)" \
        role assignment create --assignee-object-id "$WORKER_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "Storage Queue Data Message Sender" --scope "$queue_dead_scope"
    # sbci-worker blob access: read+delete ONLY via the custom split role — the
    # worker reads evidence under lease and deletes it on terminal transitions;
    # it never writes new evidence.
    ensure_custom_role "$BLOB_WORKER_ROLE_NAME" "$BLOB_WORKER_ROLE_TEMPLATE"
    run "role assignment: sbci-worker -> \"$BLOB_WORKER_ROLE_NAME\" (read/delete) on $BLOB_CONTAINER" \
        role assignment create --assignee-object-id "$WORKER_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "$BLOB_WORKER_ROLE_NAME" --scope "$blob_scope"
}

# ── Foundry (Cognitive Services / AI Foundry) ────────────────────────────

ensure_foundry_account() {
    if ! exists "cognitive services (Foundry) account $FOUNDRY_NAME" \
        cognitiveservices account show -g "$RG" -n "$FOUNDRY_NAME"; then
        run "create $FOUNDRY_LABEL Foundry account $FOUNDRY_NAME (kind AIServices, sku S0)" \
            cognitiveservices account create -g "$RG" -n "$FOUNDRY_NAME" -l "$LOCATION" \
            --kind AIServices --sku S0 --custom-domain "$FOUNDRY_NAME" --yes
        if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
            printf '  [note]  real ContentLogging attestation (gap 5.1) is NOT provisioned by this script.\n'
            printf '          Azure AIServices does not expose properties.contentLogging as a readable ARM\n'
            printf '          property in every subscription state; the operator-attested override\n'
            printf '          (SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE) must be ABSENT from the production\n'
            printf '          container-app revision once Modified Abuse Monitoring approval lands and the\n'
            printf '          real IMDS-backed ARM canary (cmd/observer-cloud, gap 5.1/D6) is wired instead —\n'
            printf '          see docs/cloud-intelligence-staging-launch-runbook.md §14.\n'
        fi
    fi
    capture FOUNDRY_ID "Foundry account resource id" \
        cognitiveservices account show -g "$RG" -n "$FOUNDRY_NAME" --query id -o tsv
}

ensure_luna_deployment() {
    if exists "Foundry deployment $LUNA_DEPLOYMENT_NAME" \
        cognitiveservices account deployment show -g "$RG" -n "$FOUNDRY_NAME" \
        --deployment-name "$LUNA_DEPLOYMENT_NAME"; then
        return 0
    fi
    if [ "$LUNA_MODEL_NAME" = "REPLACE_WITH_REAL_LUNA_MODEL_NAME" ]; then
        printf '  [plan]  SKIPPING luna deployment create — LUNA_MODEL_NAME/LUNA_MODEL_VERSION are still\n'
        printf '          placeholders. Set them (see README) and re-run to provision the real deployment.\n'
        printf '          would-run: az cognitiveservices account deployment create -g %s -n %s --deployment-name %s --model-name %s --model-version %s --model-format %s --sku-name %s --sku-capacity %s\n' \
            "$RG" "$FOUNDRY_NAME" "$LUNA_DEPLOYMENT_NAME" "$LUNA_MODEL_NAME" "$LUNA_MODEL_VERSION" \
            "$LUNA_MODEL_FORMAT" "$LUNA_SKU" "$LUNA_CAPACITY"
        return 0
    fi
    run "create luna Global Standard deployment on $FOUNDRY_NAME" \
        cognitiveservices account deployment create -g "$RG" -n "$FOUNDRY_NAME" \
        --deployment-name "$LUNA_DEPLOYMENT_NAME" --model-name "$LUNA_MODEL_NAME" \
        --model-version "$LUNA_MODEL_VERSION" --model-format "$LUNA_MODEL_FORMAT" \
        --sku-name "$LUNA_SKU" --sku-capacity "$LUNA_CAPACITY"
}

# ── Custom least-privilege roles ──────────────────────────────────────────

# ensure_custom_role <role-name> <template-path> — render the definition with
# the live subscription id and create-or-update it. The ASSIGNMENT (at a narrow
# scope) is done by the caller, matching the canary pattern. Idempotent:
# updates the definition if it already exists.
ensure_custom_role() {
    local role_name="$1" template="$2" rendered
    rendered="$(mktemp /tmp/cloudintel-role.XXXXXX.json)"
    sed -e "s#<SUBSCRIPTION_ID>#${SUBSCRIPTION_ID}#g" -e "s#<SBCI_ENV>#${SBCI_ENV}#g" "$template" >"$rendered"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  render %s with the live subscription id -> %s\n' "$template" "$rendered"
        printf '  [check] custom role "%s"\n          az role definition list --custom-role-only true --query "[?roleName==%s]" -o tsv\n          (dry-run: treated as NOT FOUND, so create is planned; a live re-run updates instead)\n' \
            "$role_name" "'$role_name'"
        printf '  [plan]  create-or-update custom role definition "%s"\n          az role definition create --role-definition %s\n' \
            "$role_name" "$rendered"
        rm -f "$rendered"
        return 0
    fi
    if azquery_raw role definition list --custom-role-only true \
        --query "[?roleName=='${role_name}']" -o tsv | grep -q .; then
        run "update custom role definition \"$role_name\"" \
            role definition update --role-definition "$rendered"
    else
        run "create custom role definition \"$role_name\"" \
            role definition create --role-definition "$rendered"
    fi
    rm -f "$rendered"
}

# ── Custom canary-reader role ─────────────────────────────────────────────

ensure_canary_role() {
    local rendered
    rendered="$(mktemp /tmp/cloudintel-canary-role.XXXXXX.json)"
    sed -e "s#<SUBSCRIPTION_ID>#${SUBSCRIPTION_ID}#g" -e "s#<SBCI_ENV>#${SBCI_ENV}#g" "$CANARY_ROLE_TEMPLATE" >"$rendered"

    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  render %s with the live subscription id -> %s\n' \
            "$CANARY_ROLE_TEMPLATE" "$rendered"
        printf '  [check] custom role "%s"\n          az role definition list --custom-role-only true --query "[?roleName==%s]" -o tsv\n          (dry-run: treated as NOT FOUND, so the create step below is included)\n' \
            "$CANARY_ROLE_NAME" "'$CANARY_ROLE_NAME'"
        printf '  [plan]  create custom role definition "%s"\n          az role definition create --role-definition %s\n' \
            "$CANARY_ROLE_NAME" "$rendered"
    else
        if azquery_raw role definition list --custom-role-only true \
            --query "[?roleName=='${CANARY_ROLE_NAME}']" -o tsv | grep -q .; then
            printf '  [check] custom role "%s" — found, skipping create\n' "$CANARY_ROLE_NAME"
        else
            run "create custom role definition \"$CANARY_ROLE_NAME\"" \
                role definition create --role-definition "$rendered"
        fi
        rm -f "$rendered"
    fi

    run "role assignment: sbci-worker -> \"$CANARY_ROLE_NAME\" scoped to $FOUNDRY_NAME ONLY (not the subscription)" \
        role assignment create --assignee-object-id "$WORKER_IDENTITY_PRINCIPAL_ID" \
        --assignee-principal-type ServicePrincipal --role "$CANARY_ROLE_NAME" --scope "$FOUNDRY_ID"
}

# ── Container Apps ────────────────────────────────────────────────────────

# NOTE (E2 / W6rs): the api container is created here with SBCI_PG_DSN only. The
# least-privilege split DSN (SBCI_API_PG_DSN, from the sbci-api-pg-dsn secret,
# login role member of sbci_api ONLY) is provisioned by `db-bootstrap` AFTER
# `up` — the observer-cloud serve process falls back to SBCI_PG_DSN when the
# api-scoped var is unset, so this stays correct until the operator wires the
# split env (db-bootstrap prints the exact commands).
ensure_containerapp_api() {
    local secret_uri="${KV_URI}/secrets/sbci-pg-dsn"
    local edge_secret_uri="${KV_URI}/secrets/${EDGE_KV_SECRET_NAME}"
    if ! exists "container app sbci-api" containerapp show -g "$RG" -n sbci-api; then
        run "create container app sbci-api (external HTTPS ingress; Cloudflare authenticated proxy hop required)" \
            containerapp create -g "$RG" -n sbci-api --environment "$CAE_ID" \
            --image "$API_IMAGE" --args serve --user-assigned "$API_IDENTITY_ID" \
            --registry-server "$ACR" --registry-identity "$API_IDENTITY_ID" \
            --ingress external --target-port "$API_TARGET_PORT" --transport auto \
            --allow-insecure false \
            --min-replicas "$API_MIN_REPLICAS" --max-replicas "$API_MAX_REPLICAS" \
            --secrets \
                "pg-dsn=keyvaultref:${secret_uri},identityref:${API_IDENTITY_ID}" \
                "${EDGE_ACA_SECRET_NAME}=keyvaultref:${edge_secret_uri},identityref:${API_IDENTITY_ID}" \
            --env-vars \
                "SBCI_PG_DSN=secretref:pg-dsn" \
                "${EDGE_ENV_NAME}=secretref:${EDGE_ACA_SECRET_NAME}" \
                "SBCI_LISTEN=:${API_TARGET_PORT}" \
                "SBCI_EXTERNAL_BASE_URL=${EXTERNAL_BASE_URL}" \
                "SBCI_PORTAL_BASE_URL=${PORTAL_BASE_URL}" \
                "SBCI_PORTAL_HOST=${PUBLIC_PORTAL_HOST}" \
                "SBCI_API_HOST=${PUBLIC_API_HOST}" \
                "SBCI_QUEUE_MODE=pg"
    else
        # `containerapp create --secrets` only covers a new app. Existing
        # staging apps must be brought to the same authenticated-hop posture
        # explicitly; otherwise a re-run of `up` would claim success while the
        # old direct-origin path stayed open. `secret set` updates only the
        # named secret and preserves the other app secrets. Query first so an
        # already-correct reference does not cause needless Container Apps
        # configuration churn on every idempotent `up`. The ARM secret object
        # exposes keyVaultUrl/identity; an env entry that references a secret
        # exposes secretRef (not value), so these checks deliberately query
        # those distinct fields.
        local edge_secret_ref="" edge_secret_identity="" edge_env_secret_ref=""
        if [ "$DRY_RUN" != "1" ]; then
            edge_secret_ref=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.configuration.secrets[?name=='${EDGE_ACA_SECRET_NAME}'].keyVaultUrl | [0]" -o tsv || true)
            edge_secret_identity=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.configuration.secrets[?name=='${EDGE_ACA_SECRET_NAME}'].identity | [0]" -o tsv || true)
        fi
        if [ "$DRY_RUN" = "1" ] || [ "$edge_secret_ref" != "$edge_secret_uri" ] || \
            [ "$edge_secret_identity" != "$API_IDENTITY_ID" ]; then
            run "wire Key Vault edge secret reference on existing sbci-api" \
                containerapp secret set -g "$RG" -n sbci-api \
                --secrets "${EDGE_ACA_SECRET_NAME}=keyvaultref:${edge_secret_uri},identityref:${API_IDENTITY_ID}"
        else
            printf '  [check] sbci-api edge secret reference — already wired to %s\n' "$EDGE_KV_SECRET_NAME"
        fi
        if [ "$DRY_RUN" != "1" ]; then
            edge_env_secret_ref=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.template.containers[0].env[?name=='${EDGE_ENV_NAME}'].secretRef | [0]" -o tsv || true)
        fi
        if [ "$DRY_RUN" = "1" ] || [ "$edge_env_secret_ref" != "$EDGE_ACA_SECRET_NAME" ]; then
            run "require edge secret on sbci-api application routes" \
                containerapp update -g "$RG" -n sbci-api \
                --set-env-vars "${EDGE_ENV_NAME}=secretref:${EDGE_ACA_SECRET_NAME}"
        else
            printf '  [check] sbci-api edge-auth env — already wired to secretref:%s\n' "$EDGE_ACA_SECRET_NAME"
        fi
        # Existing apps may predate the two-origin/canonical-host wiring. Keep
        # the portal and device API names explicit so the Worker can pass the
        # authenticated original host while its subrequest targets ACA's FQDN.
        # Compare each value first: identical --set-env-vars calls are not
        # needed and can create a needless revision in some ACA modes.
        local canonical_env_ok=0 current_external="" current_portal_base=""
        local current_portal_host="" current_api_host="" allow_insecure=""
        if [ "$DRY_RUN" != "1" ]; then
            current_external=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.template.containers[0].env[?name=='SBCI_EXTERNAL_BASE_URL'].value | [0]" -o tsv || true)
            current_portal_base=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.template.containers[0].env[?name=='SBCI_PORTAL_BASE_URL'].value | [0]" -o tsv || true)
            current_portal_host=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.template.containers[0].env[?name=='SBCI_PORTAL_HOST'].value | [0]" -o tsv || true)
            current_api_host=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query "properties.template.containers[0].env[?name=='SBCI_API_HOST'].value | [0]" -o tsv || true)
            if [ "$current_external" = "$EXTERNAL_BASE_URL" ] && \
                [ "$current_portal_base" = "$PORTAL_BASE_URL" ] && \
                [ "$current_portal_host" = "$PUBLIC_PORTAL_HOST" ] && \
                [ "$current_api_host" = "$PUBLIC_API_HOST" ]; then
                canonical_env_ok=1
            fi
        fi
        if [ "$DRY_RUN" = "1" ] || [ "$canonical_env_ok" != "1" ]; then
            run "configure sbci-api canonical public hosts" \
                containerapp update -g "$RG" -n sbci-api \
                --set-env-vars \
                    "SBCI_EXTERNAL_BASE_URL=${EXTERNAL_BASE_URL}" \
                    "SBCI_PORTAL_BASE_URL=${PORTAL_BASE_URL}" \
                    "SBCI_PORTAL_HOST=${PUBLIC_PORTAL_HOST}" \
                    "SBCI_API_HOST=${PUBLIC_API_HOST}"
        else
            printf '  [check] sbci-api canonical public hosts — already configured\n'
        fi
        # Keep the origin HTTPS-only even when `up` is resumed against an app
        # created by an older revision of this script.
        if [ "$DRY_RUN" != "1" ]; then
            allow_insecure=$(azquery_raw containerapp show -g "$RG" -n sbci-api \
                --query properties.configuration.ingress.allowInsecure -o tsv || true)
        fi
        if [ "$DRY_RUN" = "1" ] || [ "$allow_insecure" != "false" ]; then
            run "enforce HTTPS-only ingress on sbci-api" \
                containerapp ingress update -g "$RG" -n sbci-api --allow-insecure false
        else
            printf '  [check] sbci-api ingress — HTTPS-only already configured\n'
        fi
    fi
    capture API_APP_FQDN "sbci-api ingress fqdn" \
        containerapp show -g "$RG" -n sbci-api --query properties.configuration.ingress.fqdn -o tsv
}

# NOTE (E2 / W6rs): as with the api, the worker is created with SBCI_PG_DSN only;
# its least-privilege split DSN (SBCI_WORKER_PG_DSN, from sbci-worker-pg-dsn,
# login role member of sbci_worker ONLY) is provisioned by `db-bootstrap` and
# falls back to SBCI_PG_DSN until wired.
ensure_containerapp_worker() {
    local secret_uri="${KV_URI}/secrets/sbci-pg-dsn"
    if exists "container app sbci-worker" containerapp show -g "$RG" -n sbci-worker; then
        return 0
    fi
    # gap 4.4: NO --scale-rule-* flags. A pg-mode worker (SBCI_QUEUE_MODE=pg,
    # the only mode cmd/observer-cloud implements) doesn't scale on Azure
    # Storage Queue depth — it long-polls Postgres directly — so the queue-depth
    # KEDA rule this used to install was structurally degenerate from day one
    # (type/metadata/auth resolved against infrastructure the code never reads)
    # and blocked every later secrets-touching update
    # (ContainerAppScaleRuleMissingAuth, runbook §7/§11). The correct shape for
    # a no-ingress, always-on pg-mode worker is simply min=max=1 (both default
    # to 1 above) with NO scale rule at all. An ALREADY-provisioned worker
    # (staging today) still carries the old degenerate rule — fix it in place
    # with `patch-worker-scale`, not by re-running `up` (idempotent create-or-
    # skip never touches an existing app's scale config).
    run "create container app sbci-worker (no ingress, fixed ${WORKER_MIN_REPLICAS}/${WORKER_MAX_REPLICAS} replicas, no KEDA scale rule)" \
        containerapp create -g "$RG" -n sbci-worker --environment "$CAE_ID" \
        --image "$WORKER_IMAGE" --args worker --user-assigned "$WORKER_IDENTITY_ID" \
        --registry-server "$ACR" --registry-identity "$WORKER_IDENTITY_ID" \
        --min-replicas "$WORKER_MIN_REPLICAS" --max-replicas "$WORKER_MAX_REPLICAS" \
        --secrets "pg-dsn=keyvaultref:${secret_uri},identityref:${WORKER_IDENTITY_ID}" \
        --env-vars \
            "SBCI_PG_DSN=secretref:pg-dsn" \
            "SBCI_QUEUE_MODE=pg"
}

# ── up / status / down ────────────────────────────────────────────────────

do_up() {
    echo "== cloudintel-azure.sh up  (DRY_RUN=$DRY_RUN CLOUDINTEL_APPLY=$CLOUDINTEL_APPLY) =="
    if [ "$DRY_RUN" = "1" ]; then
        echo "   Nothing below is executed. Set CLOUDINTEL_APPLY=1 (and leave DRY_RUN unset) to apply for real."
    fi
    echo
    echo "-- resource group + shared infra --"
    ensure_resource_group
    capture_subscription_id

    if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
        echo
        echo "-- network lockdown (production only — gap 4.1) --"
        ensure_prod_network
    fi

    echo
    echo "-- log analytics + container apps environment --"
    ensure_log_analytics
    ensure_container_apps_env
    capture CAE_ID "container apps environment resource id" \
        containerapp env show -g "$RG" -n "$CAE_NAME" --query id -o tsv

    echo
    echo "-- identities --"
    ensure_identity "$API_IDENTITY_NAME" API_IDENTITY
    ensure_identity "$WORKER_IDENTITY_NAME" WORKER_IDENTITY

    echo
    echo "-- key vault --"
    ensure_keyvault
    ensure_operator_kv_access
    ensure_edge_shared_secret
    ensure_kv_role_assignments
    ensure_evidence_wrap_key

    echo
    echo "-- postgres --"
    ensure_pg_admin_secret
    ensure_postgres_server
    ensure_pg_dsn_secret

    echo
    echo "-- storage (queues + evidence blob container) --"
    ensure_storage_account
    ensure_storage_queue "$QUEUE_NAME"
    ensure_storage_queue "$QUEUE_DEAD_NAME"
    ensure_blob_container
    ensure_blob_soft_delete_disabled
    ensure_lifecycle_policy
    ensure_storage_role_assignments

    echo
    echo "-- foundry (non-production) --"
    ensure_foundry_account
    ensure_luna_deployment

    echo
    echo "-- canary reader custom role --"
    ensure_canary_role

    echo
    echo "-- container apps --"
    ensure_containerapp_api
    ensure_containerapp_worker

    echo
    echo "== plan complete =="
    if [ "$DRY_RUN" != "1" ]; then
        echo "sbci-api ingress: https://${API_APP_FQDN}"
    fi
    echo "Cloudflare edge: ${EXTERNAL_BASE_URL} (${PUBLIC_API_HOST}) and ${PORTAL_BASE_URL} (${PUBLIC_PORTAL_HOST})"
    echo "                 must be Worker/proxied routes that add ${EDGE_HEADER_NAME}, ${EDGE_HOST_HEADER_NAME},"
    echo "                 and the private client identity ${EDGE_CLIENT_IP_HEADER_NAME};"
    echo "                 direct ACA application requests without the edge secret must fail closed."
    echo "NEXT: run 'db-bootstrap' to create the sbci_svc Postgres login role and rotate"
    echo "the DSN secret off the raw server admin (see README)."
    echo "See README.md for the remaining manual steps this script does not automate"
    echo "(real Luna model identifiers, the Foundry credential flip post-approval, EA/MCA +"
    echo "Modified Abuse Monitoring, and the Cloudflare Worker/proxied DNS route)."
}

# ── Admin SQL execution seam (SBCI_PG_EXEC) ──────────────────────────────
#
#   Every place db-bootstrap runs admin SQL (CREATE ROLE / ALTER ROLE / GRANT)
#   goes through pg_admin_sql_exec, which dispatches on SBCI_PG_EXEC:
#     local  - unchanged: local psql, else `az postgres flexible-server
#              execute`, both from the operator's own machine over the
#              server's public endpoint. This is the only path staging needs.
#     acajob - runs the SQL inside a Manual-trigger Container Apps Job on
#              $CAE_NAME (VNet-integrated cae-subnet), the only thing that can
#              reach a production Postgres server with no public endpoint.
#   Both branches print a REDACTED plan under DRY_RUN=1, same as every other
#   verb in this file.

# pg_admin_sql_exec_local <label> <sql> <admin_pw> - the original db-bootstrap
# behaviour, unchanged, now shared by both the sbci_svc and the split-role
# statements instead of being duplicated inline.
pg_admin_sql_exec_local() {
    local label="$1" sql="$2" admin_pw="$3"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  connect to Postgres as the admin and run (password literal REDACTED): %s\n' "$label"
        printf '          preferred: PGPASSWORD=<admin> psql "host=%s port=5432 dbname=%s user=%s sslmode=require" -v ON_ERROR_STOP=1 -c <sql>\n' \
            "$PG_FQDN" "$PG_DB" "$PG_ADMIN_USER"
        printf '          fallback (no psql): az postgres flexible-server execute -n %s -u %s -d %s --querytext <sql>\n' \
            "$PG_SERVER" "$PG_ADMIN_USER" "$PG_DB"
        printf '                              (requires: az extension add --name rdbms-connect)\n'
        return 0
    fi
    if command -v psql >/dev/null 2>&1; then
        printf '  [apply] run via local psql: %s\n' "$label"
        if PGPASSWORD="$admin_pw" psql "host=${PG_FQDN} port=5432 dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" \
            -v ON_ERROR_STOP=1 -c "$sql" >/dev/null 2>&1; then
            printf '          done\n'
        else
            echo "db-bootstrap: psql failed for: $label" >&2
            exit 1
        fi
    else
        printf '  [apply] psql not found - using az postgres flexible-server execute (rdbms-connect) for: %s\n' "$label"
        azexec_raw extension add --name rdbms-connect --yes >/dev/null 2>&1 || true
        if azexec_raw postgres flexible-server execute -n "$PG_SERVER" -u "$PG_ADMIN_USER" -p "$admin_pw" \
            -d "$PG_DB" --querytext "$sql" >/dev/null; then
            printf '          done\n'
        else
            echo "db-bootstrap: az postgres flexible-server execute failed for: $label" >&2
            exit 1
        fi
    fi
}

# _PG_ADMIN_JOB_READY / _PG_ADMIN_JOB_CREATED track state across the (up to
# two) pg_admin_sql_exec_acajob calls in a single db-bootstrap run: the job is
# created (or updated) only once, then reused via `job secret set` for every
# later SQL statement; _PG_ADMIN_JOB_CREATED gates the best-effort EXIT trap
# that deletes it (cleanup_pg_admin_job below) so a "local"-mode run, or an
# acajob run that never got past DRY_RUN, never attempts a delete.
_PG_ADMIN_JOB_READY=0
_PG_ADMIN_JOB_CREATED=0

# ensure_pg_admin_job - idempotent create-or-update of the Manual-trigger
# Container Apps Job used as the in-VNet psql runner. Uses the file's normal
# exists()/run() wrappers, so it prints and behaves exactly like every other
# ensure_* step under DRY_RUN=1 - no separate dry-run branch needed here.
ensure_pg_admin_job() {
    [ "$_PG_ADMIN_JOB_READY" = "1" ] && return 0
    local psql_conn="host=${PG_FQDN} port=5432 dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require"
    # $SBCI_SQL must stay UNEXPANDED here - it is read at container runtime
    # from the job's own secretref env var, not expanded by this script. The
    # SQL is piped to psql's stdin (-f -) rather than passed as a -c argument
    # because ACA's --args/--command cannot expand env vars themselves.
    # The job is created/updated from a YAML spec: the az CLI's --command /
    # --args flags parse dash-prefixed tokens ("-c", "-v") as their own
    # options ("unrecognized arguments: -c ..." on the first production run,
    # 2026-09-13); a YAML command array has no such ambiguity.
    local shcmd='printf "%s" "$SBCI_SQL" | psql "'"${psql_conn}"'" -v ON_ERROR_STOP=1 -f -'
    local spec cae_id
    spec="$(mktemp /tmp/cloudintel-pgjob.XXXXXX.yaml)"
    chmod 600 "$spec"
    if [ "$DRY_RUN" = "1" ]; then
        cae_id="<${CAE_NAME} resource id>"
    else
        cae_id="$(azquery_raw containerapp env show -g "$RG" -n "$CAE_NAME" --query id -o tsv | tr -d '\r')"
    fi
    {
        printf 'location: %s\n' "$LOCATION"
        printf 'name: %s\n' "$PG_ADMIN_JOB_NAME"
        printf 'type: Microsoft.App/jobs\n'
        printf 'properties:\n'
        printf '  environmentId: %s\n' "$cae_id"
        printf '  configuration:\n'
        printf '    triggerType: Manual\n'
        printf '    replicaTimeout: 600\n'
        printf '    replicaRetryLimit: 0\n'
        printf '    manualTriggerConfig:\n'
        printf '      parallelism: 1\n'
        printf '      replicaCompletionCount: 1\n'
        # pgpassword/sql are created with a non-secret placeholder value; the
        # real values are written by pg_admin_sql_exec_acajob's own `job
        # secret set` call right after this, on every invocation including
        # the first - never echoed here.
        printf '    secrets:\n'
        printf '      - name: pgpassword\n        value: placeholder\n'
        printf '      - name: sql\n        value: placeholder\n'
        printf '  template:\n'
        printf '    containers:\n'
        printf '      - image: %s\n' "$PG_ADMIN_JOB_IMAGE"
        printf '        name: %s\n' "$PG_ADMIN_JOB_CONTAINER_NAME"
        printf '        command:\n          - sh\n          - "-c"\n          - %s\n' "$(printf '%s' "$shcmd" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
        printf '        env:\n'
        printf '          - name: PGPASSWORD\n            secretRef: pgpassword\n'
        printf '          - name: SBCI_SQL\n            secretRef: sql\n'
        printf '        resources:\n          cpu: 0.25\n          memory: 0.5Gi\n'
    } >"$spec"
    if exists "container apps job $PG_ADMIN_JOB_NAME" containerapp job show -g "$RG" -n "$PG_ADMIN_JOB_NAME"; then
        run "update container apps job $PG_ADMIN_JOB_NAME from YAML (in-VNet admin SQL runner)" \
            containerapp job update -g "$RG" -n "$PG_ADMIN_JOB_NAME" --yaml "$spec"
    else
        run "create container apps job $PG_ADMIN_JOB_NAME on $CAE_NAME from YAML (Manual trigger, in-VNet admin SQL runner - SBCI_PG_EXEC=acajob)" \
            containerapp job create -g "$RG" -n "$PG_ADMIN_JOB_NAME" --yaml "$spec"
        [ "$DRY_RUN" != "1" ] && _PG_ADMIN_JOB_CREATED=1
    fi
    rm -f "$spec"
    _PG_ADMIN_JOB_READY=1
}

# cleanup_pg_admin_job - best-effort EXIT trap, registered by
# pg_admin_sql_exec_acajob's first real (non-DRY_RUN) call. Never fails the
# script (the SQL either already succeeded or already failed by the time this
# runs) and never re-arms itself.
cleanup_pg_admin_job() {
    [ "$_PG_ADMIN_JOB_CREATED" = "1" ] || return 0
    echo
    echo "-- cleanup: deleting container apps job $PG_ADMIN_JOB_NAME (best effort) --"
    azexec_raw containerapp job delete -g "$RG" -n "$PG_ADMIN_JOB_NAME" --yes >/dev/null 2>&1 \
        || echo "cleanup_pg_admin_job: delete of $PG_ADMIN_JOB_NAME failed - remove it manually" >&2
}

# pg_admin_sql_exec_acajob <label> <sql> <admin_pw> - runs one admin SQL
# statement inside the Manual-trigger Container Apps Job, polling its
# execution to completion. Registers the best-effort delete trap on its first
# real invocation.
pg_admin_sql_exec_acajob() {
    local label="$1" sql="$2" admin_pw="$3"
    if [ "$DRY_RUN" = "1" ]; then
        ensure_pg_admin_job
        printf '  [plan]  az containerapp job secret set -g %s -n %s --secrets pgpassword=<REDACTED> sql=<REDACTED, statement: %s>\n' \
            "$RG" "$PG_ADMIN_JOB_NAME" "$label"
        printf '  [plan]  az containerapp job start -g %s -n %s\n' "$RG" "$PG_ADMIN_JOB_NAME"
        printf '  [plan]  poll az containerapp job execution list -g %s -n %s every 10s for Succeeded/Failed (bounded ~10 minutes)\n' \
            "$RG" "$PG_ADMIN_JOB_NAME"
        printf '  [plan]  on Failed: az containerapp job logs show -g %s -n %s --container %s --execution <name> --tail 300\n' \
            "$RG" "$PG_ADMIN_JOB_NAME" "$PG_ADMIN_JOB_CONTAINER_NAME"
        printf '          (log tail printed with any line containing PASSWORD filtered out;\n'
        printf '           if logs show is unavailable, the Log Analytics KQL query is printed instead)\n'
        printf '  [plan]  az containerapp job delete -g %s -n %s --yes  (best-effort, at db-bootstrap exit)\n' \
            "$RG" "$PG_ADMIN_JOB_NAME"
        return 0
    fi

    trap cleanup_pg_admin_job EXIT
    ensure_pg_admin_job

    run "update container apps job secrets ($PG_ADMIN_JOB_NAME) for: $label" \
        containerapp job secret set -g "$RG" -n "$PG_ADMIN_JOB_NAME" \
        --secrets "pgpassword=${admin_pw}" "sql=${sql}"

    local exec_name=""
    capture exec_name "started execution name ($PG_ADMIN_JOB_NAME) for: $label" \
        containerapp job start -g "$RG" -n "$PG_ADMIN_JOB_NAME" --query name -o tsv
    if [ -z "$exec_name" ] || [ "$exec_name" = "None" ]; then
        # Fallback in case `job start`'s response shape doesn't carry a
        # top-level name on this az/containerapp extension version.
        capture exec_name "latest execution name for $PG_ADMIN_JOB_NAME (job start did not return one)" \
            containerapp job execution list -g "$RG" -n "$PG_ADMIN_JOB_NAME" \
            --query 'sort_by([], &properties.startTime)[-1].name' -o tsv
    fi
    if [ -z "$exec_name" ] || [ "$exec_name" = "None" ]; then
        echo "db-bootstrap: could not determine the started execution name for $PG_ADMIN_JOB_NAME" >&2
        exit 1
    fi

    printf '  [apply] polling execution %s for completion (bounded, ~10 minutes)\n' "$exec_name"
    local status="" waited=0
    while [ "$waited" -lt 60 ]; do
        status=$(azquery_raw containerapp job execution list -g "$RG" -n "$PG_ADMIN_JOB_NAME" \
            --query "[?name=='${exec_name}'].properties.status | [0]" -o tsv || true)
        case "$status" in
            Succeeded | Failed) break ;;
        esac
        sleep 10
        waited=$((waited + 1))
    done

    if [ "$status" != "Succeeded" ]; then
        echo "db-bootstrap: acajob execution $exec_name for '$label' ended with status '${status:-unknown}' (job $PG_ADMIN_JOB_NAME)" >&2
        local log_args logs
        log_args=(containerapp job logs show -g "$RG" -n "$PG_ADMIN_JOB_NAME" \
            --container "$PG_ADMIN_JOB_CONTAINER_NAME" --execution "$exec_name" --tail 300 --format text)
        if logs=$(azquery_raw "${log_args[@]}") && [ -n "$logs" ]; then
            echo "  -- log tail (any line containing PASSWORD is omitted) --" >&2
            printf '%s\n' "$logs" | grep -v 'PASSWORD' >&2 || true
        else
            echo "  'az containerapp job logs show' returned nothing (older az/containerapp extension?)." >&2
            echo "  Query the $LA_NAME Log Analytics workspace instead, e.g.:" >&2
            echo "    ContainerAppConsoleLogs_CL | where ContainerAppName_s == '${PG_ADMIN_JOB_NAME}' | order by TimeGenerated desc | take 300" >&2
        fi
        exit 1
    fi
    printf '          done (execution %s succeeded)\n' "$exec_name"
}

# pg_admin_sql_exec <label> <sql> <admin_pw> - THE single seam every
# db-bootstrap admin-SQL call site goes through. Dispatches on SBCI_PG_EXEC;
# see the section header above.
pg_admin_sql_exec() {
    if [ "$SBCI_PG_EXEC" = "acajob" ]; then
        pg_admin_sql_exec_acajob "$@"
    else
        pg_admin_sql_exec_local "$@"
    fi
}

# db-bootstrap — the one-time Postgres connecting-login-role step (contract §2,
# formerly a manual README step). Generates an sbci_svc LOGIN password, stores
# it in Key Vault, runs CREATE ROLE sbci_svc LOGIN + GRANT sbci_app TO sbci_svc
# (as the admin, via psql if present else `az postgres flexible-server execute`
# with the rdbms-connect extension, or (under SBCI_PG_EXEC=acajob) a Manual
# Container Apps Job on the estate's own VNet, see pg_admin_sql_exec above),
# then rotates the sbci-pg-dsn Key Vault secret to the sbci_svc DSN so the
# apps stop connecting as the raw server admin (which is BYPASSRLS/owner-
# adjacent - contract §2 forbids it for the app).
do_db_bootstrap() {
    echo "== cloudintel-azure.sh db-bootstrap  (DRY_RUN=$DRY_RUN CLOUDINTEL_APPLY=$CLOUDINTEL_APPLY SBCI_PG_EXEC=$SBCI_PG_EXEC) =="
    if [ "$DRY_RUN" = "1" ]; then
        echo "   Nothing below is executed. Set CLOUDINTEL_APPLY=1 (and leave DRY_RUN unset) to apply for real."
    fi
    if [ "$SBCI_PG_EXEC" = "acajob" ]; then
        echo "   SBCI_PG_EXEC=acajob: admin SQL runs inside a Container Apps Job on $CAE_NAME"
        echo "   instead of from this machine - see README \"Production: in-VNet admin SQL\"."
    fi
    echo

    local admin_secret="sbci-pg-admin-password"
    local svc_secret="sbci-svc-password"
    local dsn_secret="sbci-pg-dsn"
    PG_FQDN="${PG_SERVER}.postgres.database.azure.com"

    echo "-- resolve the admin password + mint the sbci_svc password --"
    local admin_pw svc_pw
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  read the Postgres admin password from Key Vault (value REDACTED)\n'
        printf '          az keyvault secret show --vault-name %s --name %s --query value -o tsv\n' "$KV_NAME" "$admin_secret"
        printf '  [plan]  generate a new sbci_svc login password (32 random [A-Za-z0-9], value REDACTED)\n'
        admin_pw="<dry-run:kv-admin-pw>"
        svc_pw="<dry-run:generated-svc-pw>"
    else
        admin_pw="$(azquery_raw keyvault secret show --vault-name "$KV_NAME" --name "$admin_secret" --query value -o tsv || true)"
        if [ -z "$admin_pw" ]; then
            echo "db-bootstrap: could not read $admin_secret from Key Vault $KV_NAME — run 'up' first." >&2
            exit 1
        fi
        register_secret "pg-admin-password" "$admin_pw"
        svc_pw="$(gen_password)"
        register_secret "pg-svc-password" "$svc_pw"
    fi

    echo
    echo "-- store the sbci_svc password to Key Vault --"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  az keyvault secret set --vault-name %s --name %s --value <REDACTED, 32 random chars>\n' \
            "$KV_NAME" "$svc_secret"
    else
        run "store generated sbci_svc password to Key Vault ($svc_secret)" \
            keyvault secret set --vault-name "$KV_NAME" --name "$svc_secret" --value "$svc_pw"
    fi

    echo
    echo "-- create the sbci_svc login role + grant sbci_app (as admin, via SBCI_PG_EXEC=$SBCI_PG_EXEC) --"
    # Idempotent: create only if absent, then (re)set the password and grant.
    # svc_pw is [A-Za-z0-9] only (gen_password strips everything else), so it is
    # safe inside the single-quoted PASSWORD literal.
    #
    # ORDER-INDEPENDENT with migration 0015 (found by the first real prod apply,
    # 2026-09-13): 0015's tail grants sbci_api + sbci_worker TO sbci_svc only
    # when sbci_svc already exists at migrate time. Production ran migrate
    # BEFORE db-bootstrap, so that guard was a no-op and both apps logged
    # "permission denied to set role" on first boot. The mirrored guard below
    # grants the two split roles whenever THEY already exist, so whichever of
    # migrate / db-bootstrap runs second completes the membership. Both guards
    # are idempotent (GRANT of an existing membership is a NOTICE, not an error).
    local sql
    sql="DO \$do\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sbci_svc') THEN CREATE ROLE sbci_svc LOGIN; END IF; END \$do\$; ALTER ROLE sbci_svc WITH LOGIN PASSWORD '${svc_pw}'; GRANT sbci_app TO sbci_svc; DO \$do\$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sbci_api') THEN GRANT sbci_api TO sbci_svc; END IF; IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sbci_worker') THEN GRANT sbci_worker TO sbci_svc; END IF; END \$do\$;"
    pg_admin_sql_exec "CREATE ROLE sbci_svc LOGIN + GRANT sbci_app (+ sbci_api/sbci_worker when 0015 already ran)" "$sql" "$admin_pw"

    echo
    echo "-- rotate $dsn_secret to the sbci_svc DSN --"
    local dsn="postgresql://sbci_svc:${svc_pw}@${PG_FQDN}:5432/${PG_DB}?sslmode=require"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  az keyvault secret set --vault-name %s --name %s --value <REDACTED, sbci_svc DSN>\n' \
            "$KV_NAME" "$dsn_secret"
    else
        register_secret "pg-dsn" "$dsn"
        run "rotate $dsn_secret to the sbci_svc login DSN" \
            keyvault secret set --vault-name "$KV_NAME" --name "$dsn_secret" --value "$dsn"
        # Readback guard. A DSN stored with literal surrounding quotes
        # ("postgresql://...") does NOT fail loudly: pgx cannot parse the leading
        # quote as a URL scheme, silently falls back to a local unix socket as
        # user=<container-os-user> with an empty dbname, and the app crash-loops
        # with "dial unix /tmp/.s.PGSQL.5432: no such file or directory". This
        # bit the first staging apply when the DSN was rotated by hand (the
        # `az postgres flexible-server execute` path hangs under the WSL interop,
        # so the rotate was done manually and picked up surrounding quotes). Read
        # the secret back and refuse to proceed unless it parses as a bare URL.
        # This is a Key Vault read (az keyvault secret show), not a Postgres
        # connection, so it is unaffected by SBCI_PG_EXEC and needs no seam -
        # it works identically against a VNet-integrated (no public endpoint)
        # Postgres server.
        local stored
        stored=$(azquery_raw keyvault secret show --vault-name "$KV_NAME" --name "$dsn_secret" --query value -o tsv)
        case "$stored" in
            postgresql://sbci_svc:*|postgres://sbci_svc:*)
                printf '          verified: %s stores a bare postgresql:// DSN\n' "$dsn_secret" ;;
            *)
                echo "db-bootstrap: $dsn_secret did NOT store a bare postgresql:// DSN" >&2
                echo "  (a leading quote or whitespace makes pgx fall back to a unix socket and crash-loop)" >&2
                echo "  re-set it WITHOUT surrounding quotes, e.g. via --file to avoid all shell/interop quoting:" >&2
                echo "    printf '%s' '<dsn>' > /tmp/dsn.txt && az keyvault secret set --vault-name $KV_NAME --name $dsn_secret --file /tmp/dsn.txt && rm -f /tmp/dsn.txt" >&2
                exit 1 ;;
        esac
    fi

    echo
    echo "-- E2 / W6rs: provision the split login roles sbci_api_svc + sbci_worker_svc --"
    # Two dedicated LOGIN principals, each a member of ONE least-privilege
    # application role. Migration 0015 created the NOLOGIN roles sbci_api /
    # sbci_worker + their grants, and (guard block) granted BOTH to sbci_svc so
    # the single-principal staging window keeps working. THIS step provisions the
    # real two-principal separation the substrate contract wants: the api
    # container connects with SBCI_API_PG_DSN (member of sbci_api ONLY) and the
    # worker with SBCI_WORKER_PG_DSN (member of sbci_worker ONLY). sbci_svc and
    # the admin sbci-pg-dsn stay intact (migrate/grant-plan/prove still use them).
    local api_secret="sbci-api-pg-dsn" worker_secret="sbci-worker-pg-dsn"
    local api_pw worker_pw
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  generate sbci_api_svc + sbci_worker_svc login passwords (32 random [A-Za-z0-9] each, REDACTED)\n'
        api_pw="<dry-run:generated-api-pw>"
        worker_pw="<dry-run:generated-worker-pw>"
    else
        api_pw="$(gen_password)"; register_secret "api-svc-password" "$api_pw"
        worker_pw="$(gen_password)"; register_secret "worker-svc-password" "$worker_pw"
    fi

    # Idempotent, mirroring the sbci_svc block: create only if absent, (re)set the
    # password, and grant the matching role. Passwords are [A-Za-z0-9] only
    # (gen_password strips the rest), so they are safe inside the single-quoted
    # PASSWORD literals.
    local split_sql
    split_sql="DO \$do\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sbci_api_svc') THEN CREATE ROLE sbci_api_svc LOGIN; END IF; IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sbci_worker_svc') THEN CREATE ROLE sbci_worker_svc LOGIN; END IF; END \$do\$; ALTER ROLE sbci_api_svc WITH LOGIN PASSWORD '${api_pw}'; ALTER ROLE sbci_worker_svc WITH LOGIN PASSWORD '${worker_pw}'; GRANT sbci_api TO sbci_api_svc; GRANT sbci_worker TO sbci_worker_svc; GRANT sbci_aggregator TO sbci_worker_svc;"
    pg_admin_sql_exec "CREATE ROLE sbci_api_svc/sbci_worker_svc LOGIN + split GRANTs" "$split_sql" "$admin_pw"

    echo
    echo "-- store the split DSNs to Key Vault ($api_secret / $worker_secret) --"
    local api_dsn="postgresql://sbci_api_svc:${api_pw}@${PG_FQDN}:5432/${PG_DB}?sslmode=require"
    local worker_dsn="postgresql://sbci_worker_svc:${worker_pw}@${PG_FQDN}:5432/${PG_DB}?sslmode=require"
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  az keyvault secret set --vault-name %s --name %s --value <REDACTED, sbci_api_svc DSN>\n' "$KV_NAME" "$api_secret"
        printf '  [plan]  az keyvault secret set --vault-name %s --name %s --value <REDACTED, sbci_worker_svc DSN>\n' "$KV_NAME" "$worker_secret"
    else
        register_secret "api-pg-dsn" "$api_dsn"
        run "store $api_secret (sbci_api_svc login DSN)" \
            keyvault secret set --vault-name "$KV_NAME" --name "$api_secret" --value "$api_dsn"
        register_secret "worker-pg-dsn" "$worker_dsn"
        run "store $worker_secret (sbci_worker_svc login DSN)" \
            keyvault secret set --vault-name "$KV_NAME" --name "$worker_secret" --value "$worker_dsn"
        # Same bare-URL readback guard as the sbci_svc DSN: a leading quote makes
        # pgx fall back to a unix socket and crash-loop. Also a Key Vault read
        # only (see the sbci_svc readback above) - no SBCI_PG_EXEC seam needed.
        local pair sec usr stored
        for pair in "${api_secret}:sbci_api_svc" "${worker_secret}:sbci_worker_svc"; do
            sec="${pair%%:*}"; usr="${pair##*:}"
            stored=$(azquery_raw keyvault secret show --vault-name "$KV_NAME" --name "$sec" --query value -o tsv)
            case "$stored" in
                postgresql://${usr}:*|postgres://${usr}:*)
                    printf '          verified: %s stores a bare postgresql:// DSN\n' "$sec" ;;
                *)
                    echo "db-bootstrap: $sec did NOT store a bare postgresql:// DSN" >&2
                    echo "  (a leading quote or whitespace makes pgx fall back to a unix socket and crash-loop)" >&2
                    exit 1 ;;
            esac
        done
    fi
    echo
    echo "  NOTE (E2 / W6rs env wiring): add the two role-scoped DSN env vars to the"
    echo "  ACA containers so each process assumes its own least-privilege role. Until"
    echo "  then both fall back to SBCI_PG_DSN (sbci_svc, granted BOTH roles by 0015's guard"
    echo "  or by this step's mirrored guard, whichever ran second),"
    echo "  so the deployment keeps working — this just completes the separation:"
    echo "    az containerapp secret set -g $RG -n sbci-api    --secrets api-pg-dsn=keyvaultref:${KV_URI}/secrets/${api_secret},identityref:\$API_IDENTITY_ID"
    echo "    az containerapp update    -g $RG -n sbci-api    --set-env-vars SBCI_API_PG_DSN=secretref:api-pg-dsn"
    echo "    az containerapp secret set -g $RG -n sbci-worker --secrets worker-pg-dsn=keyvaultref:${KV_URI}/secrets/${worker_secret},identityref:\$WORKER_IDENTITY_ID"
    echo "    az containerapp update    -g $RG -n sbci-worker --set-env-vars SBCI_WORKER_PG_DSN=secretref:worker-pg-dsn"

    echo
    echo "== db-bootstrap complete =="
    echo "Roll a new revision of BOTH apps so they pick up the rotated $dsn_secret"
    echo "(and the split $api_secret / $worker_secret once their env vars are wired):"
    echo "  az containerapp revision copy -g $RG -n sbci-api"
    echo "  az containerapp revision copy -g $RG -n sbci-worker"
    echo "(a secretref resolves the latest KV secret version on a NEW revision, not live)."
}

do_status() {
    echo "== cloudintel-azure.sh status  (DRY_RUN=$DRY_RUN) =="
    echo
    show "resource group" group show -n "$RG" --query provisioningState -o tsv
    show "container apps env" containerapp env show -g "$RG" -n "$CAE_NAME" --query properties.provisioningState -o tsv
    show "sbci-api" containerapp show -g "$RG" -n sbci-api --query properties.provisioningState -o tsv
    show "sbci-api fqdn" containerapp show -g "$RG" -n sbci-api --query properties.configuration.ingress.fqdn -o tsv
    show "sbci-api HTTPS-only" containerapp show -g "$RG" -n sbci-api --query properties.configuration.ingress.allowInsecure -o tsv
    show "sbci-api API canonical host" containerapp show -g "$RG" -n sbci-api \
        --query "properties.template.containers[0].env[?name=='SBCI_API_HOST'].value | [0]" -o tsv
    show "sbci-api portal canonical host" containerapp show -g "$RG" -n sbci-api \
        --query "properties.template.containers[0].env[?name=='SBCI_PORTAL_HOST'].value | [0]" -o tsv
    show "sbci-api portal base URL" containerapp show -g "$RG" -n sbci-api \
        --query "properties.template.containers[0].env[?name=='SBCI_PORTAL_BASE_URL'].value | [0]" -o tsv
    show "sbci-api edge secret ref" containerapp show -g "$RG" -n sbci-api \
        --query "properties.template.containers[0].env[?name=='${EDGE_ENV_NAME}'].secretRef | [0]" -o tsv
    show "edge secret metadata (value hidden)" keyvault secret show \
        --vault-name "$KV_NAME" --name "$EDGE_KV_SECRET_NAME" \
        --query "{id:id,enabled:attributes.enabled,updated:attributes.updated}" -o json
    show "sbci-worker" containerapp show -g "$RG" -n sbci-worker --query properties.provisioningState -o tsv
    show "postgres server" postgres flexible-server show -g "$RG" -n "$PG_SERVER" --query state -o tsv
    show "postgres fqdn" postgres flexible-server show -g "$RG" -n "$PG_SERVER" --query fullyQualifiedDomainName -o tsv
    show "storage account" storage account show -g "$RG" -n "$STORAGE_ACCOUNT" --query provisioningState -o tsv
    show "key vault" keyvault show -n "$KV_NAME" -g "$RG" --query properties.vaultUri -o tsv
    show "foundry account" cognitiveservices account show -g "$RG" -n "$FOUNDRY_NAME" --query properties.provisioningState -o tsv
    show "foundry endpoint" cognitiveservices account show -g "$RG" -n "$FOUNDRY_NAME" --query properties.endpoint -o tsv
    show "luna deployment" cognitiveservices account deployment show -g "$RG" -n "$FOUNDRY_NAME" --deployment-name "$LUNA_DEPLOYMENT_NAME" --query properties.provisioningState -o tsv
    show "canary reader role" role definition list --custom-role-only true --query "[?roleName=='${CANARY_ROLE_NAME}'].name" -o tsv
    show "kv wrap role" role definition list --custom-role-only true --query "[?roleName=='${KV_WRAP_ROLE_NAME}'].name" -o tsv
    show "kv unwrap role" role definition list --custom-role-only true --query "[?roleName=='${KV_UNWRAP_ROLE_NAME}'].name" -o tsv
    show "blob api role" role definition list --custom-role-only true --query "[?roleName=='${BLOB_API_ROLE_NAME}'].name" -o tsv
    show "blob worker role" role definition list --custom-role-only true --query "[?roleName=='${BLOB_WORKER_ROLE_NAME}'].name" -o tsv
    echo
    echo "  Cloudflare Worker/DNS is intentionally operator-managed (this az-only script does not call the Cloudflare API)."
    echo "  Required edge contract: ${EXTERNAL_BASE_URL} + ${PORTAL_BASE_URL} -> Worker -> ACA FQDN;"
    echo "                        Worker secret -> ${EDGE_HEADER_NAME}, original host -> ${EDGE_HOST_HEADER_NAME}."
    echo "  Run '$0 edge-check' after the Worker routes and secret are installed."
}

# http_status <url> [extra curl args...] — return an HTTP status without
# allowing a transport failure to abort the caller. This is used only by the
# opt-in edge-check verb; the check is infrastructure-read-only, but its public
# HTTP probes intentionally exercise short-lived nonce/rate-limit state.
http_status() {
    local url="$1"
    shift
    local status
    if status=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$@" "$url" 2>/dev/null); then
        printf '%s' "$status"
    else
        printf '000'
    fi
}

do_edge_check() {
    echo "== cloudintel-azure.sh edge-check  (DRY_RUN=$DRY_RUN) =="
    echo
    if [ "$DRY_RUN" = "1" ]; then
        echo "Nothing below is executed. Set CLOUDINTEL_APPLY=1 (and leave DRY_RUN unset) to run infrastructure-read-only probes."
        echo
        echo "  [plan]  resolve the ACA origin FQDN (value is not a secret)"
        echo "          az containerapp show -g $RG -n sbci-api --query properties.configuration.ingress.fqdn -o tsv"
        echo "  [plan]  probe the public API Worker route: ${EXTERNAL_BASE_URL}/v1/auth/nonce"
        echo "          expected: 2xx (the Worker adds ${EDGE_HEADER_NAME} + ${EDGE_HOST_HEADER_NAME} + ${EDGE_CLIENT_IP_HEADER_NAME})"
        echo "  [plan]  probe the public portal Worker route: ${PORTAL_BASE_URL}/portal/api/auth-config"
        echo "          expected: 2xx (the Worker preserves the app.superbased.app origin identity)"
        echo "  [plan]  probe raw ACA application routes without a secret"
        echo "          expected: non-2xx for both /v1/auth/nonce and /portal/api/auth-config"
        echo "  [plan]  probe raw ACA application routes with spoofed forwarded-IP/host headers"
        echo "          expected: non-2xx (private client identity is accepted only after edge auth)"
        echo "  [plan]  /healthz may remain a direct liveness exception for ACA probes; it carries no account/job data."
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "edge-check: curl is required for the infrastructure-read-only probes" >&2
        return 1
    fi
    local origin_fqdn public_api_status public_portal_status
    local direct_api_status direct_portal_status spoof_api_status spoof_portal_status
    capture origin_fqdn "sbci-api ingress fqdn for edge-check" \
        containerapp show -g "$RG" -n sbci-api --query properties.configuration.ingress.fqdn -o tsv
    if [ -z "$origin_fqdn" ] || [ "$origin_fqdn" = "<dry-run:sbci-api ingress fqdn>" ]; then
        echo "edge-check: sbci-api ingress FQDN is empty; run 'up' first" >&2
        return 1
    fi
    public_api_status=$(http_status "${EXTERNAL_BASE_URL}/v1/auth/nonce")
    public_portal_status=$(http_status "${PORTAL_BASE_URL}/portal/api/auth-config")
    direct_api_status=$(http_status "https://${origin_fqdn}/v1/auth/nonce")
    direct_portal_status=$(http_status "https://${origin_fqdn}/portal/api/auth-config")
    spoof_api_status=$(http_status "https://${origin_fqdn}/v1/auth/nonce" \
        -H 'CF-Connecting-IP: 203.0.113.7' \
        -H "${EDGE_HOST_HEADER_NAME}: ${PUBLIC_API_HOST}" \
        -H "${EDGE_CLIENT_IP_HEADER_NAME}: 203.0.113.7")
    spoof_portal_status=$(http_status "https://${origin_fqdn}/portal/api/auth-config" \
        -H 'CF-Connecting-IP: 203.0.113.7' \
        -H "${EDGE_HOST_HEADER_NAME}: ${PUBLIC_PORTAL_HOST}" \
        -H "${EDGE_CLIENT_IP_HEADER_NAME}: 203.0.113.7")
    printf '  public API Worker /v1/auth/nonce:          %s (expected 2xx)\n' "$public_api_status"
    printf '  public portal Worker /portal/api/auth-config: %s (expected 2xx)\n' "$public_portal_status"
    printf '  raw ACA origin API /v1/auth/nonce:         %s (expected non-2xx)\n' "$direct_api_status"
    printf '  raw ACA origin portal /portal/api/auth-config: %s (expected non-2xx)\n' "$direct_portal_status"
    printf '  raw API + spoofed edge headers:            %s (expected non-2xx)\n' "$spoof_api_status"
    printf '  raw portal + spoofed edge headers:         %s (expected non-2xx)\n' "$spoof_portal_status"
    local failed=0
    case "$public_api_status" in 2[0-9][0-9]) ;; *) failed=1 ;; esac
    case "$public_portal_status" in 2[0-9][0-9]) ;; *) failed=1 ;; esac
    case "$direct_api_status" in 2[0-9][0-9]) failed=1 ;; esac
    case "$direct_portal_status" in 2[0-9][0-9]) failed=1 ;; esac
    case "$spoof_api_status" in 2[0-9][0-9]) failed=1 ;; esac
    case "$spoof_portal_status" in 2[0-9][0-9]) failed=1 ;; esac
    if [ "$failed" = "1" ]; then
        echo "edge-check: FAILED — verify both Worker routes/secrets and the API edge gate before exposure" >&2
        return 1
    fi
    echo "edge-check: PASS — both public routes work and direct/header-spoof application requests are refused"
}

do_plan() {
    echo "== cloudintel-azure.sh plan  (SBCI_ENV=$SBCI_ENV) =="
    echo "No az calls are made by this verb — unlike 'up'/'status' in DRY_RUN mode, which"
    echo "still print (and, with CLOUDINTEL_APPLY=1, execute) a few read-only lookups such"
    echo "as 'account show'. This only prints the resolved LOCAL config for SBCI_ENV=$SBCI_ENV,"
    echo "so an operator can sanity-check names/region/SKUs BEFORE running 'up' at all."
    echo
    printf '  %-30s %s\n' "SBCI_ENV:" "$SBCI_ENV"
    printf '  %-30s %s\n' "resource group:" "$RG"
    printf '  %-30s %s\n' "location:" "$LOCATION"
    printf '  %-30s %s\n' "container apps environment:" "$CAE_NAME"
    printf '  %-30s %s\n' "log analytics workspace:" "$LA_NAME"
    printf '  %-30s %s\n' "key vault:" "$KV_NAME"
    printf '  %-30s %s\n' "storage account:" "$STORAGE_ACCOUNT"
    printf '  %-30s %s (%s, %s)\n' "postgres server:" "$PG_SERVER" "$PG_TIER" "$PG_SKU"
    printf '  %-30s %s days (geo-redundant backup: %s)\n' "postgres PITR:" "$PG_BACKUP_RETENTION_DAYS" "$PG_GEO_REDUNDANT_BACKUP"
    printf '  %-30s %s (%s)\n' "foundry account:" "$FOUNDRY_NAME" "$FOUNDRY_LABEL"
    printf '  %-30s %s\n' "api image:" "$API_IMAGE"
    printf '  %-30s %s\n' "worker image:" "$WORKER_IMAGE"
    printf '  %-30s %s / %s\n' "api replicas (min/max):" "$API_MIN_REPLICAS" "$API_MAX_REPLICAS"
    printf '  %-30s %s / %s (no KEDA scale rule — gap 4.4)\n' "worker replicas (min/max):" "$WORKER_MIN_REPLICAS" "$WORKER_MAX_REPLICAS"
    printf '  %-30s %s\n' "public API host:" "$PUBLIC_API_HOST"
    printf '  %-30s %s\n' "public portal host:" "$PUBLIC_PORTAL_HOST"
    printf '  %-30s %s\n' "external base URL:" "$EXTERNAL_BASE_URL"
    printf '  %-30s %s\n' "portal base URL:" "$PORTAL_BASE_URL"
    if [ "$SBCI_ENV_IS_PROD" = "1" ]; then
        printf '  %-30s %s (%s)\n' "vnet:" "$VNET_NAME" "$VNET_ADDRESS_PREFIX"
        printf '  %-30s %s (%s, delegated Microsoft.App/environments)\n' "container apps subnet:" "$CAE_SUBNET_NAME" "$CAE_SUBNET_PREFIX"
        printf '  %-30s %s (%s, delegated Microsoft.DBforPostgreSQL/flexibleServers)\n' "postgres subnet:" "$PG_SUBNET_NAME" "$PG_SUBNET_PREFIX"
        printf '  %-30s %s\n' "NAT gateway (worker egress):" "$NAT_GATEWAY_NAME"
    else
        printf '  %-30s %s\n' "network:" "public access (AllowAzureServices firewall rule) — VNet+NAT lockdown is production-only (gap 4.1)"
    fi
    echo
    echo "Run '$0 up' (with CLOUDINTEL_APPLY=1 for a real apply) to see the full per-resource az command plan."
}

do_patch_worker_scale() {
    local patch_file="${SCRIPT_DIR}/../../deploy/cloudintel/worker-scale-patch.yaml"
    echo "== cloudintel-azure.sh patch-worker-scale  (DRY_RUN=$DRY_RUN CLOUDINTEL_APPLY=$CLOUDINTEL_APPLY) =="
    echo
    echo "Fixes the degenerate KEDA queue-depth scale rule on an ALREADY-PROVISIONED"
    echo "sbci-worker (gap 4.4 — staging today; any env where 'up' created the worker"
    echo "before this fix landed). A fresh 'up' now creates the worker correctly (no scale"
    echo "rule, fixed replicas) — this verb is for an existing app only."
    echo
    if [ ! -f "$patch_file" ]; then
        echo "patch-worker-scale: patch file not found at $patch_file" >&2
        return 1
    fi
    run "patch sbci-worker scale (min=max=${WORKER_MIN_REPLICAS}, no KEDA rule) from $patch_file" \
        containerapp update -g "$RG" -n sbci-worker --yaml "$patch_file"
    echo
    echo "NEXT: the worker's Foundry/evidence Key Vault secretrefs (deferred in runbook §7"
    echo "because ContainerAppScaleRuleMissingAuth blocked any secrets-touching update while"
    echo "the degenerate rule stood) can now be wired without hitting that validation."
}

do_down() {
    echo "This will DELETE resource group '$RG' and everything in it: both container"
    echo "apps, the Postgres server (and all its data — no separate confirmation),"
    echo "storage account (queues + the evidence blob container), Key Vault, the"
    echo "Foundry account, and both managed identities."
    echo ""
    echo "NOT deleted by this: the Cloudflare Worker, its routes/custom domains, DNS"
    echo "records, or its encrypted edge secret. Disable both public routes (or rotate"
    echo "the secret) separately before reusing either public hostname for another origin."
    echo
    echo "NOT deleted by this: the '$CANARY_ROLE_NAME' custom role DEFINITION, which is"
    echo "subscription-scoped and outlives the resource group (role assignments referencing"
    echo "deleted resources are cleaned up by ARM; the definition itself is not). Remove it"
    echo "separately with: az role definition delete --name \"$CANARY_ROLE_NAME\""
    echo
    if [ "$DRY_RUN" = "1" ]; then
        echo "DRY_RUN=$DRY_RUN — even after confirmation below, the delete itself will only be printed, not executed."
    fi
    printf "Type the resource group name exactly to confirm deletion (%s): " "$RG"
    read -r CONFIRM
    if [ "$CONFIRM" != "$RG" ]; then
        echo "down: confirmation did not match '$RG' — aborting, nothing deleted." >&2
        exit 1
    fi
    run "delete resource group $RG (cascades every resource in it)" \
        group delete -n "$RG" --yes
}

case "${1:-}" in
up) do_up ;;
db-bootstrap) do_db_bootstrap ;;
status) do_status ;;
edge-check) do_edge_check ;;
plan) do_plan ;;
patch-worker-scale) do_patch_worker_scale ;;
down) do_down ;;
*)
    echo "usage: $0 up|db-bootstrap|status|edge-check|plan|patch-worker-scale|down" >&2
    echo "  up                  idempotent create-or-skip of the estate" >&2
    echo "  db-bootstrap        create the sbci_svc Postgres login role + rotate the DSN secret" >&2
    echo "  status              read-only show/list" >&2
    echo "  edge-check          infrastructure-read-only dual-host boundary probes (HTTP state note in README)" >&2
    echo "  plan                print the resolved names/region/SKUs for SBCI_ENV with NO az calls" >&2
    echo "  patch-worker-scale  fix an EXISTING worker's degenerate KEDA scale rule (gap 4.4)" >&2
    echo "  down                delete the RG (typed confirm)" >&2
    echo "  SBCI_ENV selects staging (default) or prod — see the header comment and README." >&2
    echo "  DRY_RUN defaults to 1 (print-only). Set CLOUDINTEL_APPLY=1 to allow real az calls." >&2
    exit 2
    ;;
esac
