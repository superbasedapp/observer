#!/usr/bin/env bash
# codesign.sh: the ONE place platform code signing slots into the release
# (T-920 phase 1 hook, T-961 Windows wiring). OFF by default: with the switch
# unset every call is a logged no-op and the file ships as built.
#
#   scripts/codesign.sh windows        <file>   Authenticode-sign, then verify
#   scripts/codesign.sh windows-verify <file>   verify only (the second check on
#                                               the setup program after makensis)
#   scripts/codesign.sh darwin         <file>   Apple Developer ID signature with
#                                               the hardened runtime, then
#                                               notarization (never stapled)
#
# Called from .github/workflows/npm-release.yml:
#   - build / edition_build: on every observer, observer-org and
#     antigravity-bridge binary for windows (and darwin), BEFORE upload, so
#     npm, PyPI, the VS Code extension and the archives all carry the same
#     signed bytes and the vendor .sig and SLSA subjects are computed over
#     them (signing changes the bytes);
#   - windows_setup: on observerw.exe, and through makensis's !finalize /
#     !uninstfinalize (-DSIGN_COMMAND) on the setup program and the
#     uninstaller it embeds.
#
# Windows (docs/release-runbook.md "Code signing"; plan
# docs/plans/code-signing-phase-2-plan-2026-10-21.md section 3.1): jsign
# signs with the Gaja AI Private Limited OV certificate held in Azure Key
# Vault (storetype AZUREKEYVAULT; the private key is RSA-HSM and never leaves
# the vault), an RFC 3161 timestamp is mandatory, then osslsigncode checks
# that the result names the publisher and carries a timestamp. The switch is
# OBSERVER_SIGN_AUTHENTICODE=1 (a variable of the GitHub environment
# `release-signing`, never a commit). Inputs when on:
#   AZURE_SIGNING_VAULT      vault name or URI
#   AZURE_SIGNING_CERT_NAME  certificate object name in the vault
#   AZURE_SIGNING_TOKEN      Key Vault access token (the workflow fetches it
#                            after the OIDC login; jsign reads it through
#                            `--storepass env:`, so it is never on a command
#                            line, and this script never expands it)
#   JSIGN_JAR                path to the pinned jsign jar
# Optional: installer/windows/codesign-chain.pem (public certificate chain,
# passed to jsign as --certfile when the file exists; the vault already
# returns the issuing CA, so it is not needed today), CODESIGN_CAFILE (trust
# anchors for the check, default the system bundle).
#
# macOS (plan section 3.2; macsign lane): rcodesign (pinned, Linux) signs
# with the Developer ID Application certificate and the hardened runtime, and
# Apple's timestamp (rcodesign's default). Then `rcodesign verify` must pass
# and `rcodesign print-signature-info` must show the runtime flag and a
# Developer ID Application certificate of APPLE_TEAM_ID. A zipped copy goes
# to Apple's notary service (`notary-submit --wait`, at most
# NOTARY_WAIT_SECONDS); anything but "Accepted" prints the notary log and
# fails. The zip is deleted. Nothing is stapled: a bare Mach-O has no place to
# hold a ticket, so Gatekeeper looks it up online by the code hash. The switch
# is OBSERVER_SIGN_APPLE=1 (same rules as the Windows switch). Inputs when on,
# all set by sourcing scripts/codesign-apple-inputs.sh in the signing step,
# which writes the secrets to mode-600 files and deletes them at the end:
#   APPLE_P12_FILE           Developer ID Application certificate + key (P12)
#   APPLE_P12_PASSWORD_FILE  the P12's password, first line of the file
#   APPLE_NOTARY_KEY_FILE    rcodesign's encoded App Store Connect API key
#   APPLE_TEAM_ID            the 10-character Team ID the certificate must name
#   RCODESIGN                path to the pinned rcodesign binary
# Optional: installer/macos/observer.entitlements (passed as
# --entitlements-xml-file only when the file exists; none is committed, see
# plan sections 4.2 and 5 on wazero), CODESIGN_ENTITLEMENTS_FILE (test seam
# for that path).
#
# A kind that is on but cannot finish (a missing input, a signing error, a
# failed check) exits non-zero and fails the release; it never ships an
# unsigned file quietly. Never add `set -x` here.
#
# This script references no key, certificate or secret.

set -euo pipefail

# The publisher the Authenticode check expects in the signer's subject. Same
# value as PUBLISHER in installer/windows/superbased-setup.nsi.
EXPECTED_PUBLISHER="Gaja AI Private Limited"
TSA_URLS="http://timestamp.sectigo.com,http://timestamp.digicert.com"
# The identifier every macOS binary is signed with, and the longest the
# release waits for Apple's notary answer per binary (seconds).
APPLE_BINARY_IDENTIFIER="app.superbased.observer"
NOTARY_WAIT_SECONDS=1800

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chain_file="${CODESIGN_CHAIN_FILE:-${repo_root}/installer/windows/codesign-chain.pem}"
entitlements_file="${CODESIGN_ENTITLEMENTS_FILE:-${repo_root}/installer/macos/observer.entitlements}"

kind="${1:-}"
file="${2:-}"
if [ -z "$kind" ] || [ -z "$file" ]; then
    echo "usage: scripts/codesign.sh windows|windows-verify|darwin <file>" >&2
    exit 2
fi
if [ ! -f "$file" ]; then
    echo "codesign: no such file: $file" >&2
    exit 2
fi

fail() {
    echo "::error::codesign: $*" >&2
    exit 1
}

# switch_on NAME: true when the switch is "1", false when it is unset, empty
# or "0"; any other value is a typo that must not ship unsigned bytes quietly.
switch_on() {
    local value="${!1:-}"
    case "$value" in
        1) return 0 ;;
        "" | 0) return 1 ;;
        *) fail "$1 must be 1 (on) or unset (off), not '$value'" ;;
    esac
}

# active_switch names the switch of the kind being run, for the messages.
active_switch=OBSERVER_SIGN_AUTHENTICODE

# require NAME...: every named input must be set and non-empty. Indirect
# expansion, so a secret input's value is never spelled out in this file.
require() {
    local name
    for name in "$@"; do
        if [ -z "${!name:-}" ]; then
            fail "${active_switch}=1 but $name is not set"
        fi
    done
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "${active_switch}=1 but $1 is not installed"
}

# require_file NAME...: the named input must point at a non-empty file.
require_file() {
    local name
    for name in "$@"; do
        [ -s "${!name}" ] || fail "${active_switch}=1 but $name does not point at a non-empty file"
    done
}

# verify_authenticode FILE: osslsigncode must accept the signature against
# the trust anchors, name the expected publisher and show a timestamp.
verify_authenticode() {
    local f="$1" name out cafile tmp_ca=""
    name="$(basename "$f")"
    require_tool osslsigncode
    cafile="${CODESIGN_CAFILE:-/etc/ssl/certs/ca-certificates.crt}"
    [ -f "$cafile" ] || fail "trust anchors not found: $cafile (set CODESIGN_CAFILE)"
    if [ -f "$chain_file" ]; then
        tmp_ca="$(mktemp)"
        cat "$cafile" "$chain_file" >"$tmp_ca"
        cafile="$tmp_ca"
    fi
    # The token never reaches the checker's environment.
    if ! out="$(env -u AZURE_SIGNING_TOKEN osslsigncode verify -in "$f" -CAfile "$cafile" 2>&1)"; then
        [ -z "$tmp_ca" ] || rm -f "$tmp_ca"
        printf '%s\n' "$out" >&2
        fail "osslsigncode verify rejected the signature on $name"
    fi
    [ -z "$tmp_ca" ] || rm -f "$tmp_ca"
    printf '%s\n' "$out"
    if ! printf '%s\n' "$out" | grep -Eq "Subject:.*${EXPECTED_PUBLISHER}"; then
        fail "the signature on $name does not name ${EXPECTED_PUBLISHER}"
    fi
    if ! printf '%s\n' "$out" | grep -Eq 'The signature is timestamped:|Timestamp Server Signature verification: ok'; then
        fail "the signature on $name carries no timestamp"
    fi
    echo "codesign: $name is signed by ${EXPECTED_PUBLISHER}, timestamped and verified"
}

# sign_darwin FILE: sign with the Developer ID and the hardened runtime,
# check the signature, then notarize a zipped copy and require "Accepted".
sign_darwin() {
    local f="$1" name info out notary_dir zip_file submission
    name="$(basename "$f")"
    local entitlements_args=()
    if [ -f "$entitlements_file" ]; then
        entitlements_args=(--entitlements-xml-file "$entitlements_file")
    fi
    echo "codesign: signing $name with the Developer ID of team ${APPLE_TEAM_ID} (hardened runtime)"
    if ! "$RCODESIGN" sign \
        --p12-file "$APPLE_P12_FILE" \
        --p12-password-file "$APPLE_P12_PASSWORD_FILE" \
        --code-signature-flags runtime \
        --for-notarization \
        --binary-identifier "$APPLE_BINARY_IDENTIFIER" \
        ${entitlements_args[@]+"${entitlements_args[@]}"} \
        "$f"; then
        fail "rcodesign could not sign $name"
    fi
    if ! "$RCODESIGN" verify "$f"; then
        fail "rcodesign verify rejected the signature on $name"
    fi
    if ! info="$("$RCODESIGN" print-signature-info "$f" 2>&1)"; then
        printf '%s\n' "$info" >&2
        fail "rcodesign print-signature-info could not read the signature on $name"
    fi
    printf '%s\n' "$info"
    # The code directory's flags (not executable_segment_flags) carry RUNTIME.
    if ! printf '%s\n' "$info" | grep -Eq '(^|[[:space:]])flags: .*RUNTIME'; then
        fail "the signature on $name lacks the hardened runtime flag"
    fi
    if ! printf '%s\n' "$info" | grep -Eq '(^|[[:space:]])apple_certificate_profile: developer-id-application[[:space:]]*$'; then
        fail "the signature on $name is not made with a Developer ID Application certificate"
    fi
    if ! printf '%s\n' "$info" | grep -Eq "(^|[[:space:]])apple_team_id: ['\"]?${APPLE_TEAM_ID}['\"]?[[:space:]]*\$"; then
        fail "the signing certificate on $name does not name team ${APPLE_TEAM_ID}"
    fi
    echo "codesign: $name is signed with the Developer ID of team ${APPLE_TEAM_ID}, hardened runtime, verified"

    # Apple's notary service takes a zip, not a bare Mach-O. The zip is a
    # throwaway: the shipped file stays the signed binary itself.
    notary_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codesign-notary.XXXXXX")"
    # shellcheck disable=SC2064 # expand the path now, the local is gone later
    trap "rm -rf '$notary_dir'" EXIT
    zip_file="${notary_dir}/${name}.zip"
    if ! zip -j -X -q "$zip_file" "$f"; then
        fail "could not zip $name for notarization"
    fi
    echo "codesign: submitting $name to Apple's notary service (waiting up to ${NOTARY_WAIT_SECONDS}s)"
    if out="$("$RCODESIGN" notary-submit --api-key-file "$APPLE_NOTARY_KEY_FILE" --wait --max-wait-seconds "$NOTARY_WAIT_SECONDS" "$zip_file" 2>&1)" &&
        printf '%s\n' "$out" | grep -Eq 'poll state after [0-9]+s: Accepted'; then
        printf '%s\n' "$out"
        rm -rf "$notary_dir"
        trap - EXIT
        echo "codesign: $name signed with the Developer ID of team ${APPLE_TEAM_ID}, notarization Accepted"
        return 0
    fi
    printf '%s\n' "$out" >&2
    submission="$(printf '%s\n' "$out" | sed -n 's/.*created submission ID: \([A-Za-z0-9-]*\).*/\1/p' | head -n 1)"
    if [ -n "$submission" ]; then
        echo "codesign: the notary log of submission $submission:" >&2
        "$RCODESIGN" notary-log --api-key-file "$APPLE_NOTARY_KEY_FILE" "$submission" >&2 || true
    fi
    rm -rf "$notary_dir"
    trap - EXIT
    fail "notarization of $name was not Accepted"
}

case "$kind" in
    windows)
        if ! switch_on OBSERVER_SIGN_AUTHENTICODE; then
            echo "codesign: Authenticode is off (phase 2); $(basename "$file") ships unsigned"
            exit 0
        fi
        require AZURE_SIGNING_VAULT AZURE_SIGNING_CERT_NAME AZURE_SIGNING_TOKEN JSIGN_JAR
        [ -f "$JSIGN_JAR" ] || fail "JSIGN_JAR does not exist: $JSIGN_JAR"
        require_tool java
        require_tool osslsigncode
        certfile_args=()
        if [ -f "$chain_file" ]; then
            certfile_args=(--certfile "$chain_file")
        fi
        echo "codesign: signing $(basename "$file") with ${AZURE_SIGNING_CERT_NAME} from ${AZURE_SIGNING_VAULT}"
        if ! java -jar "$JSIGN_JAR" \
            --storetype AZUREKEYVAULT \
            --keystore "$AZURE_SIGNING_VAULT" \
            --alias "$AZURE_SIGNING_CERT_NAME" \
            --storepass env:AZURE_SIGNING_TOKEN \
            ${certfile_args[@]+"${certfile_args[@]}"} \
            --alg SHA-256 \
            --tsaurl "$TSA_URLS" \
            --tsmode RFC3161 \
            --replace \
            --name "SuperBased Observer" \
            --url https://superbased.app \
            "$file"; then
            fail "jsign could not sign $(basename "$file")"
        fi
        verify_authenticode "$file"
        ;;
    windows-verify)
        if ! switch_on OBSERVER_SIGN_AUTHENTICODE; then
            echo "codesign: Authenticode is off (phase 2); not checking $(basename "$file")"
            exit 0
        fi
        verify_authenticode "$file"
        ;;
    darwin)
        if ! switch_on OBSERVER_SIGN_APPLE; then
            echo "codesign: Apple signing and notarization are off (phase 2); $(basename "$file") ships with Go's ad-hoc signature only"
            exit 0
        fi
        active_switch=OBSERVER_SIGN_APPLE
        require APPLE_P12_FILE APPLE_P12_PASSWORD_FILE APPLE_NOTARY_KEY_FILE APPLE_TEAM_ID RCODESIGN
        require_file APPLE_P12_FILE APPLE_P12_PASSWORD_FILE APPLE_NOTARY_KEY_FILE
        [ -x "$RCODESIGN" ] || fail "RCODESIGN is not an executable file: $RCODESIGN"
        if ! [[ "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
            fail "APPLE_TEAM_ID must be the 10-character Team ID (capital letters and digits), not '$APPLE_TEAM_ID'"
        fi
        require_tool zip
        # rcodesign reads every RCODESIGN_<KEY> environment variable as a
        # configuration key and stops with "configuration file error" on one
        # it does not know; the workflow's RCODESIGN_VERSION and
        # RCODESIGN_SHA256 pins are such keys (the v1.37.0 failure), so none
        # reaches it. RCODESIGN itself (no suffix) is not read by it.
        for rcodesign_var in $(compgen -e); do
            case "$rcodesign_var" in RCODESIGN_*) unset "$rcodesign_var" ;; esac
        done
        sign_darwin "$file"
        ;;
    *)
        echo "codesign: unknown kind '$kind' (want windows, windows-verify or darwin)" >&2
        exit 2
        ;;
esac
