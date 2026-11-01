# codesign-apple-inputs.sh: turns the Apple signing secrets of the release
# into the files scripts/codesign.sh darwin reads (macsign lane, plan
# docs/plans/code-signing-phase-2-plan-2026-10-21.md sections 2.2, 3.2 and
# 3.3). SOURCE it, do not run it: it exports the file paths into the calling
# step's shell and arms an EXIT trap there that deletes the files when that
# shell ends.
#
#   . scripts/codesign-apple-inputs.sh
#   scripts/codesign.sh darwin <file>
#   scripts/codesign.sh darwin <file>
#
# OBSERVER_SIGN_APPLE unset, empty or 0: a logged no-op that reads no input
# (codesign.sh darwin is then a logged no-op too). 1: on. Anything else fails.
#
# Inputs when on (the signing step's env; secrets are passed only when the
# switch is 1 on a v* tag):
#   APPLE_DEVELOPER_ID_P12_BASE64    secret: the Developer ID Application P12,
#                                    base64
#   APPLE_DEVELOPER_ID_P12_PASSWORD  secret: the P12's password
#   APPLE_TEAM_ID                    variable: the 10-character Team ID
#   RCODESIGN                        path to the pinned rcodesign binary
# and exactly ONE form of the notarization key:
#   APPLE_NOTARY_API_KEY_JSON        secret: rcodesign's encoded key (the
#                                    output of encode-app-store-connect-api-key)
# or the three raw parts, encoded here with that same rcodesign command:
#   APPLE_NOTARY_ISSUER_ID           variable: the Issuer ID (a UUID)
#   APPLE_NOTARY_KEY_ID              variable: the Key ID (10 characters)
#   APPLE_NOTARY_KEY_P8              secret: the text of AuthKey_<id>.p8
#
# Outputs (exported): APPLE_P12_FILE, APPLE_P12_PASSWORD_FILE,
# APPLE_NOTARY_KEY_FILE, each mode 600 inside one mode-700 directory under
# $RUNNER_TEMP. The four secret variables are unset afterwards so no child
# process inherits them. A secret value is only ever expanded into a
# `printf '%s'` that writes its file (a shell builtin, so never on a command
# line), never echoed and never written to GITHUB_ENV; the one value derived
# here (the encoded key's private key) is masked. Never add `set -x` here.

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "::error::codesign: source scripts/codesign-apple-inputs.sh (. scripts/codesign-apple-inputs.sh); do not run it" >&2
    exit 2
fi

_cai_fail() {
    echo "::error::codesign: $*" >&2
    exit 1
}

# _cai_set NAME: true when the named variable is set and non-empty. Indirect
# expansion, so a secret's value is not spelled out here.
_cai_set() {
    [ -n "${!1:-}" ]
}

_cai_cleanup() {
    if [ -n "${_cai_dir:-}" ]; then
        rm -rf "$_cai_dir"
    fi
}

_cai_main() {
    case "${OBSERVER_SIGN_APPLE:-}" in
        1) ;;
        "" | 0)
            echo "codesign: Apple signing is off; no Apple signing input is read"
            return 0
            ;;
        *) _cai_fail "OBSERVER_SIGN_APPLE must be 1 (on) or unset (off), not '${OBSERVER_SIGN_APPLE}'" ;;
    esac

    local name
    for name in APPLE_DEVELOPER_ID_P12_BASE64 APPLE_DEVELOPER_ID_P12_PASSWORD APPLE_TEAM_ID RCODESIGN RUNNER_TEMP; do
        _cai_set "$name" || _cai_fail "OBSERVER_SIGN_APPLE=1 but $name is not set"
    done
    [ -d "$RUNNER_TEMP" ] || _cai_fail "RUNNER_TEMP is not a directory: $RUNNER_TEMP"
    [ -x "$RCODESIGN" ] || _cai_fail "RCODESIGN is not an executable file: $RCODESIGN"

    # Exactly one form of the notarization key. Any raw part counts as the
    # raw form, so a forgotten APPLE_NOTARY_KEY_ID beside the JSON is caught
    # rather than silently ignored.
    local key_form="" raw_any=0
    for name in APPLE_NOTARY_ISSUER_ID APPLE_NOTARY_KEY_ID APPLE_NOTARY_KEY_P8; do
        if _cai_set "$name"; then raw_any=1; fi
    done
    if _cai_set APPLE_NOTARY_API_KEY_JSON; then
        if [ "$raw_any" = 1 ]; then
            _cai_fail "both forms of the notarization key are set: use APPLE_NOTARY_API_KEY_JSON alone, or APPLE_NOTARY_ISSUER_ID + APPLE_NOTARY_KEY_ID + APPLE_NOTARY_KEY_P8, not both"
        fi
        key_form=json
    elif [ "$raw_any" = 1 ]; then
        for name in APPLE_NOTARY_ISSUER_ID APPLE_NOTARY_KEY_ID APPLE_NOTARY_KEY_P8; do
            _cai_set "$name" || _cai_fail "OBSERVER_SIGN_APPLE=1 with the raw notarization key parts, but $name is not set"
        done
        if ! [[ "$APPLE_NOTARY_ISSUER_ID" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; then
            _cai_fail "APPLE_NOTARY_ISSUER_ID must be the Issuer ID shown in App Store Connect (a UUID)"
        fi
        if ! [[ "$APPLE_NOTARY_KEY_ID" =~ ^[A-Z0-9]{10}$ ]]; then
            _cai_fail "APPLE_NOTARY_KEY_ID must be the 10-character Key ID shown in App Store Connect"
        fi
        key_form=raw
    else
        _cai_fail "OBSERVER_SIGN_APPLE=1 but no notarization key is set: set APPLE_NOTARY_API_KEY_JSON, or APPLE_NOTARY_ISSUER_ID + APPLE_NOTARY_KEY_ID + APPLE_NOTARY_KEY_P8"
    fi

    local old_umask
    old_umask="$(umask)"
    umask 077
    _cai_dir="$(mktemp -d "${RUNNER_TEMP%/}/codesign-apple.XXXXXX")" || _cai_fail "cannot create a private directory in RUNNER_TEMP"
    trap _cai_cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    chmod 700 "$_cai_dir"

    if ! printf '%s' "$APPLE_DEVELOPER_ID_P12_BASE64" | base64 -d >"$_cai_dir/developer-id.p12" 2>/dev/null; then
        _cai_fail "APPLE_DEVELOPER_ID_P12_BASE64 is not valid base64 (base64 -w0 of the .p12 file)"
    fi
    [ -s "$_cai_dir/developer-id.p12" ] || _cai_fail "APPLE_DEVELOPER_ID_P12_BASE64 decodes to an empty file"
    printf '%s\n' "$APPLE_DEVELOPER_ID_P12_PASSWORD" >"$_cai_dir/developer-id.p12.password"

    if [ "$key_form" = json ]; then
        printf '%s\n' "$APPLE_NOTARY_API_KEY_JSON" >"$_cai_dir/notary-key.json"
    else
        printf '%s\n' "$APPLE_NOTARY_KEY_P8" >"$_cai_dir/AuthKey.p8"
        # rcodesign reads the .p8 file; the secret variables stay out of its
        # environment. So does every RCODESIGN_<KEY> variable: rcodesign
        # reads each as a configuration key and stops with "configuration
        # file error" on one it does not know, such as the workflow's
        # RCODESIGN_VERSION and RCODESIGN_SHA256 pins (the v1.37.0 failure).
        local _cai_rc_unset=() _cai_v
        for _cai_v in $(compgen -e); do
            case "$_cai_v" in RCODESIGN_*) _cai_rc_unset+=(-u "$_cai_v") ;; esac
        done
        if ! env -u APPLE_DEVELOPER_ID_P12_BASE64 -u APPLE_DEVELOPER_ID_P12_PASSWORD \
            -u APPLE_NOTARY_API_KEY_JSON -u APPLE_NOTARY_KEY_P8 \
            ${_cai_rc_unset[@]+"${_cai_rc_unset[@]}"} \
            "$RCODESIGN" encode-app-store-connect-api-key -o "$_cai_dir/notary-key.json" \
            "$APPLE_NOTARY_ISSUER_ID" "$APPLE_NOTARY_KEY_ID" "$_cai_dir/AuthKey.p8"; then
            _cai_fail "rcodesign could not encode the notarization key from APPLE_NOTARY_ISSUER_ID, APPLE_NOTARY_KEY_ID and APPLE_NOTARY_KEY_P8"
        fi
        rm -f "$_cai_dir/AuthKey.p8"
        [ -s "$_cai_dir/notary-key.json" ] || _cai_fail "rcodesign wrote no encoded notarization key"
    fi
    chmod 600 "$_cai_dir"/*
    umask "$old_umask"

    # The encoded key's private_key is base64 DER: in the raw form no secret
    # holds it verbatim, and in the JSON form it is only a part of the
    # secret, so it is masked on its own before anything else runs.
    local derived
    derived="$(grep -o '"private_key"[[:space:]]*:[[:space:]]*"[^"]*"' "$_cai_dir/notary-key.json" | sed 's/.*"\([^"]*\)"$/\1/' | head -n 1 || true)"
    if [ -n "$derived" ]; then
        echo "::add-mask::${derived}"
    fi
    derived=""

    export APPLE_P12_FILE="$_cai_dir/developer-id.p12"
    export APPLE_P12_PASSWORD_FILE="$_cai_dir/developer-id.p12.password"
    export APPLE_NOTARY_KEY_FILE="$_cai_dir/notary-key.json"
    unset APPLE_DEVELOPER_ID_P12_BASE64 APPLE_DEVELOPER_ID_P12_PASSWORD APPLE_NOTARY_API_KEY_JSON APPLE_NOTARY_KEY_P8
    echo "codesign: Apple signing inputs ready (notarization key: ${key_form} form); they are deleted when this step ends"
}

_cai_main
