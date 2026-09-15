#!/usr/bin/env bash
# alerts.sh — creates Azure Monitor scheduled-query + metric alert rules for
# the Cloud Intelligence estate (gap 4.6 / D7). Companion to
# cloudintel-azure.sh (same DRY_RUN/CLOUDINTEL_APPLY double gate, same
# SBCI_ENV parameterization) but kept as its OWN script rather than a verb on
# that one — alert rules are an operations concern layered on TOP of an
# already-provisioned estate, never part of `up`'s create-or-skip idempotency,
# and an operator may want to iterate on alert thresholds without touching
# infrastructure at all.
#
# NEVER RUN in this session (standing rule) — this script's apply-mode path
# (CLOUDINTEL_APPLY=1) is author-only, exactly like cloudintel-azure.sh's own
# apply path was on first authoring. Read scripts/cloudintel/README.md and
# docs/cloud-intelligence-staging-launch-runbook.md §10/§14 first.
#
#   scripts/cloudintel/alerts/alerts.sh plan     print what would be created, no az calls
#   scripts/cloudintel/alerts/alerts.sh up        idempotent create-or-skip of every alert rule
#
# What this creates:
#   1. A LOG alert on revision-unhealthy.kql (ContainerAppSystemLogs_CL)
#   2. A LOG alert on healthz-and-restarts.kql (best-effort /healthz proxy —
#      see that file's header for the honest limitation)
#   3. METRIC alerts on the Postgres Flexible Server's own platform metrics
#      (active_connections, storage_percent) — these ARE real Azure Monitor
#      metrics, no app-level logging needed
#   4. An action group the above route to (email-only; the address is an env
#      var, never hardcoded — see ALERT_EMAIL below)
#
# What this does NOT create (and why — see webhook-5xx-and-audit-bursts.sql's
# header for the full explanation): a Log Analytics alert for webhook 5xx
# rate, paddle_webhook_signature_invalid bursts, portal_workos_state_mismatch
# bursts, or job park rate. Those three signals exist ONLY as Postgres rows
# today (security_audit_events / analysis_jobs) — the app never logs them to
# stdout, so Log Analytics (which is what Azure Monitor scheduled-query
# alerts read) has nothing to query. Run webhook-5xx-and-audit-bursts.sql on
# an operator-scheduled cadence (cron + psql, or an Azure Automation Runbook)
# until a follow-up wave adds a structured stdout log line alongside every
# `s.audit(...)` call in internal/cloudserver/api — the same pattern the rest
# of this repo uses ("owed" rather than silently fabricated).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SBCI_ENV="${SBCI_ENV:-staging}"
case "$SBCI_ENV" in
    staging | prod) ;;
    *)
        echo "alerts.sh: SBCI_ENV must be 'staging' or 'prod' (got '$SBCI_ENV')" >&2
        exit 2
        ;;
esac

if [ "$SBCI_ENV" = "prod" ]; then
    RG="${RG:-superbased-cloudintel-prod-rg}"
    LA_NAME="${LA_NAME:-sbci-prod-logs}"
    PG_SERVER="${PG_SERVER:-sbci-prod-pg}"
    ACTION_GROUP_NAME="${ACTION_GROUP_NAME:-sbci-prod-alerts}"
else
    RG="${RG:-superbased-cloudintel-staging-rg}"
    LA_NAME="${LA_NAME:-sbci-staging-logs}"
    PG_SERVER="${PG_SERVER:-sbci-staging-pg}"
    ACTION_GROUP_NAME="${ACTION_GROUP_NAME:-sbci-staging-alerts}"
fi

# The action-group destination — NAME ONLY, never hardcoded. The operator
# supplies the real address; this script refuses to create the action group
# without it (an alert nobody receives is worse than no alert — it looks
# monitored and isn't).
ALERT_EMAIL="${ALERT_EMAIL:-}"
# Absolute active-connection count for the PG early-warning alert (see the
# note beside the rule): NOT a percentage of max_connections.
PG_CONN_THRESHOLD="${PG_CONN_THRESHOLD:-80}"

CLOUDINTEL_APPLY="${CLOUDINTEL_APPLY:-0}"
if [ "$CLOUDINTEL_APPLY" = "1" ]; then
    DRY_RUN="${DRY_RUN:-0}"
else
    DRY_RUN=1
fi

run() { # run <label> <az args...>
    local label="$1"; shift
    if [ "$DRY_RUN" = "1" ]; then
        printf '  [plan]  %s\n          az %s\n' "$label" "$*"
        return 0
    fi
    printf '  [apply] %s\n' "$label"
    az "$@" -o none
    printf '          done\n'
}

kql_inline() { # kql_inline <file>  -> one-line KQL, comments stripped, single-quoted strings
    grep -v '^[[:space:]]*//' "$1" | grep -v '^[[:space:]]*$' | tr '\n' ' ' | sed "s/\"/'/g; s/[[:space:]]*$//"
}

do_plan_or_up() {
    local verb="$1"
    echo "== alerts.sh $verb  (SBCI_ENV=$SBCI_ENV DRY_RUN=$DRY_RUN CLOUDINTEL_APPLY=$CLOUDINTEL_APPLY) =="
    if [ "$DRY_RUN" = "1" ]; then
        echo "   Nothing below is executed. Set CLOUDINTEL_APPLY=1 (and leave DRY_RUN unset) to apply for real."
    fi
    echo

    if [ -z "$ALERT_EMAIL" ]; then
        echo "  [note]  ALERT_EMAIL is unset — the action group step below is a NO-OP plan only."
        echo "          Set ALERT_EMAIL=<address> before a real apply."
    fi

    if [ "$DRY_RUN" != "1" ] && [ -z "$ALERT_EMAIL" ]; then
        echo "alerts.sh: refusing to apply without ALERT_EMAIL - an alert nobody receives looks monitored and isn't" >&2
        return 1
    fi

    echo
    echo "-- action group --"
    run "create/update action group $ACTION_GROUP_NAME (email: ${ALERT_EMAIL:-<unset>})" \
        monitor action-group create -g "$RG" -n "$ACTION_GROUP_NAME" --short-name sbcialert \
        --action email sbci-oncall "${ALERT_EMAIL:-REPLACE_WITH_ALERT_EMAIL}"

    # The alert rules below reference the action group by RESOURCE ID. Plan
    # mode cannot know it, so it prints a placeholder; apply mode resolves it
    # right after the create above (first exercised for real 2026-09-14).
    local ag_id
    if [ "$DRY_RUN" = "1" ]; then
        ag_id="sbci-${SBCI_ENV}-alerts-ag-id-placeholder"
    else
        ag_id=$(az monitor action-group show -g "$RG" -n "$ACTION_GROUP_NAME" --query id -o tsv | tr -d '\r\n')
        [ -n "$ag_id" ] || { echo "alerts.sh: could not resolve the action group id" >&2; return 1; }
    fi

    # KQL bodies go INLINE: the scheduled-query extension's --condition-query
    # takes NAME=QUERY and does not expand @file inside the pair (found at the
    # first real apply, 2026-09-14 - it sent the literal path and Azure answered
    # "No tabular expression statement found"). kql_inline drops // comment
    # lines, joins the rest on spaces, and swaps double quotes for KQL single
    # quotes so the argument survives the WSL->Windows az argv round-trip.

    local la_id
    if [ "$DRY_RUN" = "1" ]; then
        la_id="<dry-run:log-analytics-workspace-id>"
    else
        la_id=$(az monitor log-analytics workspace show -g "$RG" -n "$LA_NAME" --query id -o tsv | tr -d '\r\n')
    fi

    echo
    echo "-- log-query alerts (Log Analytics workspace $LA_NAME) --"
    run "create scheduled-query alert: revision unhealthy (sbci-api/sbci-worker)" \
        monitor scheduled-query create -g "$RG" -n "sbci-${SBCI_ENV}-revision-unhealthy" \
        --scopes "$la_id" --condition "count 'query' > 0" \
        --condition-query "query=$(kql_inline "${SCRIPT_DIR}/revision-unhealthy.kql")" \
        --window-size 10m --evaluation-frequency 5m --severity 2 \
        --action-groups "$ag_id"
    run "create scheduled-query alert: /healthz-proxy restart burst (sbci-api)" \
        monitor scheduled-query create -g "$RG" -n "sbci-${SBCI_ENV}-healthz-restarts" \
        --scopes "$la_id" --condition "count 'query' > 0" \
        --condition-query "query=$(kql_inline "${SCRIPT_DIR}/healthz-and-restarts.kql")" \
        --window-size 15m --evaluation-frequency 5m --severity 2 \
        --action-groups "$ag_id"

    echo
    echo "-- metric alerts (Postgres Flexible Server $PG_SERVER) --"
    local pg_id
    if [ "$DRY_RUN" = "1" ]; then
        pg_id="<dry-run:postgres-flexible-server-resource-id>"
    else
        pg_id=$(az postgres flexible-server show -g "$RG" -n "$PG_SERVER" --query id -o tsv | tr -d '\r\n')
    fi
    # PG_CONN_THRESHOLD is an ABSOLUTE connection count, not a percentage:
    # the prod server (D2ds_v4) has max_connections=859, so 80 is an early
    # warning at ~9% of the ceiling - two pooled apps never legitimately hold
    # that many. (The label used to say "80% of max", which it never was.)
    run "create metric alert: PG active_connections > ${PG_CONN_THRESHOLD} (absolute count, early warning)" \
        monitor metrics alert create -g "$RG" -n "sbci-${SBCI_ENV}-pg-connections" \
        --scopes "$pg_id" --condition "avg active_connections > ${PG_CONN_THRESHOLD}" \
        --window-size 5m --evaluation-frequency 1m --severity 2 \
        --action "$ag_id"
    run "create metric alert: PG storage_percent > 85%" \
        monitor metrics alert create -g "$RG" -n "sbci-${SBCI_ENV}-pg-storage" \
        --scopes "$pg_id" --condition "avg storage_percent > 85" \
        --window-size 5m --evaluation-frequency 5m --severity 2 \
        --action "$ag_id"

    echo
    echo "== $verb complete =="
    if [ "$DRY_RUN" = "1" ]; then
        echo "NOTE: the --action-groups/--action placeholder above stands in for the action"
        echo "group's real resource id; apply mode resolves it right after creating the group."
    fi
    echo
    echo "STILL OWED (see webhook-5xx-and-audit-bursts.sql): webhook 5xx rate,"
    echo "paddle_webhook_signature_invalid bursts, portal_workos_state_mismatch bursts, and"
    echo "job park rate have no Log Analytics signal today (the app never logs them to"
    echo "stdout) — run that SQL file on an operator cadence until a follow-up wave adds"
    echo "structured logging alongside every audit()/park-state-transition call."
}

case "${1:-}" in
plan) DRY_RUN=1; do_plan_or_up plan ;;
up) do_plan_or_up up ;;
*)
    echo "usage: $0 plan|up" >&2
    echo "  plan   print every az command that would run, with NO az calls" >&2
    echo "  up     idempotent create-or-skip (set CLOUDINTEL_APPLY=1 for a real apply)" >&2
    echo "  SBCI_ENV selects staging (default) or prod." >&2
    echo "  ALERT_EMAIL is required for a real apply (action-group destination)." >&2
    exit 2
    ;;
esac
