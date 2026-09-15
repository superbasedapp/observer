#!/usr/bin/env bash
# demo-azure.sh — turn the Azure org-observer demo estate on/off on demand.
#
#   scripts/demo-azure.sh up       start all four container groups, probe health
#   scripts/demo-azure.sh down     stop (deallocate) all four groups
#   scripts/demo-azure.sh status   provisioning state + live health probes
#
# To UPDATE the org image after a code change (recreate sb-org on a new
# observer-org tag), use scripts/roll-org.sh — NOT this script. Full lifecycle:
# docs/hosted-surfaces-runbook.md.
#
# NOTE (2026-09-04): the "az is WINDOWS-ONLY" claim below is now STALE for this
# RG — native Linux az handled the entire org roll. winaz is kept as a fallback.
#
# The estate (RG superbased-demo-rg, eastus — see
# docs/demo-environment-playbook.md for the full map):
#
#   sb-org        org server :9443 (+ harness-gateway + saml-idp sidecars)
#   sb-gateway    observer gateway :8820 (the demo LLM lane)
#   sb-chat-demo  Open WebUI :8080 (the client demo)
#   sb-demo-ch    ClickHouse :8123 (EPHEMERAL — contents reset on down/up;
#                 the org server re-creates the schema on demand and the
#                 parquet SoR on the sb-org-data share is the durable record)
#   sb-devfleet   two simulated developer nodes (devnode-asha,
#                 devnode-miguel) replaying claude-code sessions and
#                 pushing Plane-B activity to sb-org (no public ports)
#
# az is WINDOWS-ONLY on this box: every call goes through cmd.exe, and the
# WSL<->Windows interop channel flakes under load, so each call retries.
# Stopped ACI groups bill no compute; Azure Files shares persist regardless.
# DNS labels (FQDNs) survive down/up; public IPs churn — nothing here
# references IPs.

set -u

RG=superbased-demo-rg
GROUPS_ALL=(sb-org sb-gateway sb-chat-demo sb-demo-ch sb-devfleet)

ORG_URL="http://sborg35022.eastus.azurecontainer.io:9443"
GW_URL="http://sbgateway35022.eastus.azurecontainer.io:8820"
CHAT_URL="http://sbchatdemo35022.eastus.azurecontainer.io:8080"
CH_URL="http://sbdemoch35022.eastus.azurecontainer.io:8123"

# Run one az command via Windows cmd.exe, retrying through interop flakes.
winaz() {
    local out i
    for i in $(seq 1 10); do
        out=$(cd /mnt/c && cmd.exe /c "$1" 2>/dev/null | tr -d '\r')
        if [ -n "$out" ]; then printf '%s\n' "$out"; return 0; fi
        sleep 5
    done
    echo "winaz: FAILED after 10 tries: $1" >&2
    return 1
}

probe() { # probe <name> <url>
    local code
    code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$2" 2>/dev/null)
    printf '  %-14s %s -> %s\n' "$1" "$2" "${code:-unreachable}"
}

case "${1:-}" in
up)
    for g in "${GROUPS_ALL[@]}"; do
        echo "starting $g ..."
        winaz "az container start -g $RG -n $g -o none && echo STARTED-$g" | tail -1
    done
    echo "waiting for health ..."
    for i in $(seq 1 30); do
        ok=$(curl -s -m 5 "$ORG_URL/healthz" 2>/dev/null)
        [ -n "$ok" ] && break
        sleep 10
    done
    probe org "$ORG_URL/healthz"
    probe gateway "$GW_URL/-/healthz"
    probe chat "$CHAT_URL"
    probe clickhouse "$CH_URL/ping"
    echo
    echo "org dashboard: $ORG_URL  (dev login: POST /auth/dev/login email=admin@example.com)"
    echo "demo chat:     $CHAT_URL"
    ;;
down)
    for g in "${GROUPS_ALL[@]}"; do
        echo "stopping $g ..."
        winaz "az container stop -g $RG -n $g -o none && echo STOPPED-$g" | tail -1
    done
    echo "note: sb-demo-ch contents are gone on next start (schema self-heals)."
    ;;
status)
    for g in "${GROUPS_ALL[@]}"; do
        st=$(winaz "az container show -g $RG -n $g --query instanceView.state -o tsv" || echo unknown)
        printf '  %-14s %s\n' "$g" "$st"
    done
    echo
    probe org "$ORG_URL/healthz"
    probe gateway "$GW_URL/-/healthz"
    probe chat "$CHAT_URL"
    probe clickhouse "$CH_URL/ping"
    ;;
*)
    echo "usage: $0 up|down|status" >&2
    exit 2
    ;;
esac
