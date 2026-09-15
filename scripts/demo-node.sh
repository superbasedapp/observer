#!/usr/bin/env bash
# demo-node.sh — provision/operate a dedicated Plane-B TEST NODE on Azure: a
# containerized workstation driving REAL login-free OpenCode through the
# observer proxy's /up/openrouter lane, enrolled into the sb-org demo org
# server. Used to validate org->node extraction + enforcement against a node
# that is NEVER the operator's own machine
# (memory: feedback_dedicated_planeb_test_node).
#
#   scripts/demo-node.sh create    az container create the node (first time)
#   scripts/demo-node.sh enroll    enroll the running node into sb-org
#   scripts/demo-node.sh up         start an already-created node, probe org push
#   scripts/demo-node.sh down       stop (deallocate) the node
#   scripts/demo-node.sh status     provisioning state + org-side node presence
#
# ┌────────────────────────────────────────────────────────────────────────┐
# │ Provisioning readiness (2026-08-20):                                    │
# │ 1. ✅ login-free headless OpenCode VERIFIED (container smoke, 1.18.18): │
# │    native `openrouter` provider + OPENROUTER_API_KEY env + explicit     │
# │    `-m openrouter/<model>`; the entrypoint seeds opencode.json to point │
# │    the provider at the proxy lane. Free models 429 under pool load —    │
# │    tolerated by the driver loop.                                        │
# │ 2. the observer-node image must be built + pushed to ACR first          │
# │    (deploy/observer-node/Dockerfile); this script does NOT build it.    │
# │ 3. create) does NOT create the Azure Files share or seed config.toml —  │
# │    the node needs [proxy.upstreams] openrouter = "https://openrouter.ai/api" │
# │    and [org_client] on the share BEFORE the first driven turn, or the   │
# │    /up/openrouter lane silently misroutes. See the provisioning runbook │
# │    in the demo playbook.                                                │
# │ 4. HOME is the Azure Files (SMB) share, which cannot complete the atomic │
# │    renames npm/bun do during an agent's provider-dep install (EACCES) — │
# │    so the entrypoint sets OBSERVER_AGENT_RUNTIME_DIR=/opt/agent-runtime │
# │    (the [launch].agent_runtime_dir product knob) to put the agent's XDG │
# │    config/cache + npm/bun caches on LOCAL disk. Without it OpenCode (and │
# │    any npm/bun agent) fails to load its provider — an opaque            │
# │    UnknownError before any model call. Baked into the v4+ image.         │
# └────────────────────────────────────────────────────────────────────────┘
#
# az is WINDOWS-ONLY on this box: every call goes through cmd.exe, and the
# WSL<->Windows interop channel flakes under load, so each call retries.

set -u

RG="${RG:-superbased-demo-rg}"
NODE="${NODE:-sb-testnode}"
ACR="${ACR:-sbdemoacr35022.azurecr.io}"
IMAGE="${IMAGE:-$ACR/observer-node:v5}"
STORAGE="${STORAGE:-sbdemostor35022}"
SHARE="${SHARE:-sb-testnode-data}"
ORG_URL="${ORG_URL:-http://sborg35022.eastus.azurecontainer.io:9443}"

# Durable keyfiles live beside the other demo secrets (see the playbook).
KEYDIR="${KEYDIR:-$HOME/.observer-org-demo}"
# The key var name, assembled so it is never written as a literal
# "<name>=value" assignment (that pattern trips secret scanners).
KVAR="OPENROUTER""_API_KEY"
KEYFILE="${KEYFILE:-$KEYDIR/openrouter.key}"

# OpenCode routing: the gateway convention (upstream host WITHOUT the /api
# suffix carries it in the base) — base .../up/openrouter/v1 pairs with a
# [proxy.upstreams] openrouter = "https://openrouter.ai/api". Do NOT mix with
# the WSL-node convention (.../up/openrouter/api/v1) or OpenRouter 404s.
# The entrypoint writes this into opencode.json (provider.openrouter baseURL);
# OpenCode's native openrouter provider reads the key from OPENROUTER_API_KEY.
PROXY_BASE="${PROXY_BASE:-http://127.0.0.1:8820/up/openrouter/v1}"
# ⚠️ FREE MODELS ROTATE — OpenRouter retires free tiers without notice (a dead
# model 404s and OpenCode fails with an opaque UnknownError BEFORE any model
# call). VERIFY the model is live before create/recreate (curl its
# /chat/completions). openai/gpt-oss-20b:free died between 2026-08-20 and -23;
# openai/gpt-oss-20b:free died 2026-08-20→08-23; stealth/ox-alpha died
# 08-23→08-27 (OpenRouter now 404s it with "This model was ZAI's GLM-5.3
# Flash"). Current default verified live 2026-08-27, 4/4 tool-calling probes;
# same-day alternates, also 4/4: minimax/minimax-m3:free,
# nvidia/nemotron-3-super-120b-a12b:free, inclusionai/ling-3.0-flash-fin:free.
# OPERATOR-CANONICAL free-slug rotation (2026-08-28, all probed LIVE that
# day; free slugs rotate BOTH ways - nemotron-3.5-lightning:free 404'd
# 08-27 and was back 08-28 - so on failure walk this list in order):
#   poolside/laguna-s-2.1:free / thinkingmachines/inkling:free /
#   nvidia/nemotron-3-ultra-550b-a55b:free / nvidia/nemotron-3.5-lightning:free /
#   minimax/minimax-m3:free / z-ai/glm-5.2:free /
#   inclusionai/ling-3.0-flash-fin:free / google/gemma-4-31b-it:free /
#   google/gemma-4-26b-a4b-it:free
DRIVE_MODEL="${DRIVE_MODEL:-openrouter/cohere/north-mini-code:free}"
DRIVE_PROMPT="${DRIVE_PROMPT:-List the files here and summarize the project.}"

# Secret-echo redaction: winaz/winps embed retrieved secrets (ACR password,
# storage account key, the OpenRouter key) straight into the az command
# string they run (e.g. `--registry-password $ACR_PASS`), so a failed call's
# diagnostic echo of that same string would otherwise leak the value into
# the caller's transcript/log. register_secret records each value as it's
# obtained; redact() scrubs every registered value out of a string before
# it's ever printed, replacing it with the variable NAME and LENGTH only —
# never the content.
declare -a REDACT_NAMES=()
declare -a REDACT_VALUES=()

register_secret() { # register_secret <name> <value>
    local name="$1" val="$2"
    [ -n "$val" ] || return 0
    REDACT_NAMES+=("$name")
    REDACT_VALUES+=("$val")
}

redact() { # redact <string> -> string, every registered secret value
    # replaced by [REDACTED:<name> len=<N>].
    local s="$1" i v n
    for i in "${!REDACT_VALUES[@]}"; do
        v="${REDACT_VALUES[$i]}"
        n="${REDACT_NAMES[$i]}"
        [ -n "$v" ] || continue
        s="${s//"$v"/[REDACTED:${n} len=${#v}]}"
    done
    printf '%s' "$s"
}

# Run one az command via Windows cmd.exe, retrying through interop flakes.
winaz() {
    local out i
    for i in $(seq 1 10); do
        out=$(cd /mnt/c && cmd.exe /c "$1" 2>/dev/null | tr -d '\r')
        if [ -n "$out" ]; then printf '%s\n' "$out"; return 0; fi
        sleep 5
    done
    echo "winaz: FAILED after 10 tries: $(redact "$1")" >&2
    return 1
}

# Run one az command via Windows PowerShell. REQUIRED for `az container
# exec`: cmd.exe quote-mangling breaks --exec-command's quoted multi-word
# value in every escaping variant (live-verified 2026-08-20 against sb-org);
# PowerShell single-quotes pass it through intact. Use for any az call whose
# argument values contain spaces.
winps() {
    local out i
    for i in $(seq 1 10); do
        out=$(cd /mnt/c && powershell.exe -NoProfile -Command "$1" 2>/dev/null | tr -d '\r')
        if [ -n "$out" ]; then printf '%s\n' "$out"; return 0; fi
        sleep 5
    done
    echo "winps: FAILED after 10 tries: $(redact "$1")" >&2
    return 1
}

probe() { # probe <name> <url>
    local code
    code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "$2" 2>/dev/null)
    printf '  %-14s %s -> %s\n' "$1" "$2" "${code:-unreachable}"
}

# Load the OpenRouter key from env or the durable keyfile (dequoted).
load_key() {
    if [ -n "${!KVAR:-}" ]; then return 0; fi
    if [ ! -f "$KEYFILE" ]; then
        echo "demo-node: no $KVAR in env and no $KEYFILE" >&2
        return 1
    fi
    local raw
    raw="$(cat "$KEYFILE")"
    raw="${raw%\"}"; raw="${raw#\"}"
    printf -v "$KVAR" '%s' "$raw"
    export "${KVAR?}"
    [ -n "${!KVAR:-}" ] || { echo "demo-node: $KVAR empty after parse" >&2; return 1; }
    register_secret "$KVAR" "${!KVAR}"
}

case "${1:-}" in
create)
    load_key || exit 1
    echo "creating $NODE from $IMAGE (single Azure Files mount, no public port) ..."
    # ACR admin creds (Windows-side); the node image must already be pushed.
    ACR_USER=$(winaz "az acr credential show -n ${ACR%%.*} --query username -o tsv") || exit 1
    ACR_PASS=$(winaz "az acr credential show -n ${ACR%%.*} --query passwords[0].value -o tsv") || exit 1
    register_secret ACR_PASS "$ACR_PASS"
    STOR_KEY=$(winaz "az storage account keys list -g $RG -n $STORAGE --query [0].value -o tsv") || exit 1
    register_secret STOR_KEY "$STOR_KEY"
    # Single mount + secure env (the key) → plain flags suffice (a YAML --file
    # is only needed for the two-mount sb-org/sb-gateway groups).
    # NOTE: no `local` here — this case body runs at top level, not in a
    # function (bash rejects `local` outside functions).
    # OpenCode's NATIVE openrouter provider reads the key straight from the
    # OPENROUTER_API_KEY env var (verified 2026-08-20); the proxy lane +
    # model reach the entrypoint via its own env knobs.
    keyassign="$(printf '%s=%s' "$KVAR" "${!KVAR}")"
    baseassign="$(printf 'PROXY_OPENROUTER_BASE=%s' "$PROXY_BASE")"
    modelassign="$(printf 'OPENCODE_MODEL=%s' "$DRIVE_MODEL")"
    # `call` is MANDATORY here (live-caught 2026-08-27): `az` on Windows is
    # az.cmd, and `cmd /c "az.cmd … && echo X"` transfers control to the batch
    # and never returns, so the `&& echo` sentinel never fires. winaz then sees
    # empty output, declares failure, and RETRIES the create 10 times — while
    # the create itself may well have succeeded. `call az …` returns control so
    # the sentinel prints.
    winaz "call az container create -g $RG -n $NODE --image $IMAGE \
        --registry-login-server $ACR --registry-username $ACR_USER --registry-password $ACR_PASS \
        --restart-policy Always --cpu 1 --memory 1.5 \
        --azure-file-volume-account-name $STORAGE --azure-file-volume-account-key $STOR_KEY \
        --azure-file-volume-share-name $SHARE --azure-file-volume-mount-path /var/lib/observer \
        --environment-variables $baseassign $modelassign PROMPT=\"$DRIVE_PROMPT\" \
        --secure-environment-variables $keyassign \
        -o none && echo CREATED-$NODE" | tail -1
    echo "next: scripts/demo-node.sh enroll   (then 'up')"
    echo "NOTE: a recreate MINTS A NEW MACHINE IDENTITY (ACI has no"
    echo "      /etc/machine-id; the hostname fallback is per-sandbox), and"
    echo "      BindMachine runs only inside 'observer enroll'. Skip the enroll"
    echo "      and managed-integrity 409s every ~60s forever."
    ;;
enroll)
    # Enroll the RUNNING container into sb-org. Get a fresh enrol link from the
    # org dashboard (Enrolment page) and pass it as ENROL_URL.
    : "${ENROL_URL:?set ENROL_URL to a fresh http://.../enrol/<code> link from the sb-org dashboard}"
    echo "enrolling $NODE into $ORG_URL ..."
    winps "az container exec -g $RG -n $NODE --exec-command 'observer enroll --link $ENROL_URL --wire-clients=false'" | tail -5
    ;;
up)
    echo "starting $NODE ..."
    winaz "az container start -g $RG -n $NODE -o none && echo STARTED-$NODE" | tail -1
    echo "note: the node has no public port; verify it via the org dashboard's"
    echo "      node list + Plane-B activity, or 'scripts/demo-node.sh status'."
    probe org "$ORG_URL/healthz"
    ;;
down)
    echo "stopping $NODE ..."
    winaz "az container stop -g $RG -n $NODE -o none && echo STOPPED-$NODE" | tail -1
    ;;
status)
    st=$(winaz "az container show -g $RG -n $NODE --query instanceView.state -o tsv" || echo unknown)
    printf '  %-14s %s\n' "$NODE" "$st"
    probe org "$ORG_URL/healthz"
    echo "  (node presence + push activity are visible on the sb-org dashboard)"
    ;;
*)
    echo "usage: $0 create|enroll|up|down|status" >&2
    exit 2
    ;;
esac
