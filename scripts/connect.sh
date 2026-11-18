#!/bin/sh
# connect.sh: install superbased Observer and connect this machine, in one
# step, on Linux or macOS.
#
#   curl -fsSL https://superbased.app/connect.sh | sh               # personal dashboard
#   curl -fsSL https://superbased.app/connect.sh | sh -s -- <team>  # a team
#
# It downloads the newest release's install.sh, checks it against the
# release's SHA256SUMS, checks SHA256SUMS against the vendor key below (the
# same key install.sh and internal/update/vendorkey.go carry; tests/invariant
# pins the three), then runs `sh install.sh --connect [team]`. install.sh
# verifies the Observer archive the same way before installing it, runs
# Observer as a background service that starts when you sign in, and runs
# `observer connect`: you approve this machine in your browser (or enter a
# short code on any device), and nothing is sent before you do.
#
# Arguments after the team (or every argument, when the first starts with
# '-') pass to install.sh, e.g. `sh -s -- acme --edition full`. The team may
# also come from SBO_CONNECT_TEAM. It takes no token or credential. Uses
# curl, or wget when curl is absent.
#
# An Ed25519 verifier (OpenSSL 3, Node 12+ or Python cryptography) checks the
# signature; with none, the checksum alone is used and a warning says so,
# unless SBO_REQUIRE_SIGNATURE=1, which refuses.
set -eu

# The accepted vendor verification keys, newest first: the same values as
# internal/update/vendorkey.go. tests/invariant pins them.
VENDOR_KEYS="npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="

RELEASE_URL="https://github.com/superbasedapp/observer/releases/latest/download"

say() { printf '%s\n' "$*"; }
warn() { printf 'connect.sh: WARNING: %s\n' "$*" >&2; }
die() { printf 'connect.sh: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

team="${SBO_CONNECT_TEAM:-}"
if [ $# -gt 0 ]; then
  case "$1" in -*) ;; *) team="$1"; shift ;; esac
fi
if [ -n "$team" ] && ! printf '%s\n' "$team" | grep -Eq '^[a-z0-9][a-z0-9-]{0,62}$'; then
  die "'$team' is not a team name (lowercase letters, digits and hyphens)"
fi

# Tests: SBO_CONNECT_FROM_DIR reads the release files from a directory (and
# passes --from-dir to install.sh); only then is a test vendor key honoured.
from_dir="${SBO_CONNECT_FROM_DIR:-}"
if [ -n "${OBSERVER_INSTALL_TEST_VENDOR_KEY:-}" ]; then
  [ -n "$from_dir" ] || die "OBSERVER_INSTALL_TEST_VENDOR_KEY is honoured only with SBO_CONNECT_FROM_DIR"
  VENDOR_KEYS="$OBSERVER_INSTALL_TEST_VENDOR_KEY"
fi

work=$(mktemp -d 2>/dev/null || mktemp -d -t observer-connect)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT TERM

# fetch <name> <optional 0|1>: status 0 present, 1 absent.
fetch() {
  if [ -n "$from_dir" ]; then
    if [ -f "$from_dir/$1" ]; then cp "$from_dir/$1" "$work/$1"; return 0; fi
    [ "$2" -eq 1 ] && return 1
    die "$1 is not in $from_dir"
  fi
  if have curl; then
    if curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$work/$1" "$RELEASE_URL/$1" 2>/dev/null; then return 0; fi
  elif have wget; then
    if wget -q --https-only -O "$work/$1" "$RELEASE_URL/$1"; then return 0; fi
  else
    die "need curl or wget"
  fi
  rm -f "$work/$1"
  [ "$2" -eq 1 ] && return 1
  die "could not download $RELEASE_URL/$1"
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{ print $1 }'
  elif have shasum; then shasum -a 256 "$1" | awk '{ print $1 }'
  elif have openssl; then openssl dgst -sha256 "$1" | awk '{ print $NF }'
  else die "no sha256 tool found (need sha256sum, shasum or openssl)"
  fi
}

# verify_<x> <key base64> <sig file> <message file>: 0 good, 1 bad, 2 no
# verifier. Each is trusted only after it accepts the RFC 8032 section 7.1
# TEST 1 vector (empty message) and rejects a changed signature.
verify_openssl() {
  have openssl || return 2
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$1" '-----END PUBLIC KEY-----' >"$work/vk.pem"
  openssl pkeyutl -verify -pubin -inkey "$work/vk.pem" -rawin -in "$3" -sigfile "$2" >/dev/null 2>&1
}
verify_node() {
  have node || return 2
  node -e '
    const c = require("crypto"), fs = require("fs");
    const a = process.argv.slice(1);
    if (typeof c.verify !== "function") process.exit(2);
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(a[0], "base64")]);
    const key = c.createPublicKey({ key: der, format: "der", type: "spki" });
    process.exit(c.verify(null, fs.readFileSync(a[2]), key, fs.readFileSync(a[1])) ? 0 : 1);
  ' "$1" "$2" "$3" >/dev/null 2>&1
}
verify_python() {
  have python3 || return 2
  python3 -I -c '
import base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
k = Ed25519PublicKey.from_public_bytes(base64.b64decode(sys.argv[1]))
with open(sys.argv[2], "rb") as f:
    s = f.read()
with open(sys.argv[3], "rb") as f:
    m = f.read()
k.verify(s, m)
' "$1" "$2" "$3" >/dev/null 2>&1
}

RFC_KEY="11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
RFC_SIG="5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw=="

b64d() {
  if have base64 && base64 -d </dev/null >/dev/null 2>&1; then base64 -d
  elif have base64 && base64 -D </dev/null >/dev/null 2>&1; then base64 -D
  elif have openssl; then openssl base64 -d -A
  else return 1
  fi
}

pick_verifier() {
  : >"$work/empty"
  printf '%s' "$RFC_SIG" | b64d >"$work/rfc.sig" 2>/dev/null || return 1
  cp "$work/rfc.sig" "$work/rfc-bad.sig"
  printf 'x' | dd of="$work/rfc-bad.sig" bs=1 seek=0 conv=notrunc 2>/dev/null || return 1
  for v in verify_openssl verify_node verify_python; do
    if "$v" "$RFC_KEY" "$work/rfc.sig" "$work/empty" && ! "$v" "$RFC_KEY" "$work/rfc-bad.sig" "$work/empty"; then
      verifier="$v"
      return 0
    fi
  done
  return 1
}

say "Getting the superbased Observer installer."
fetch SHA256SUMS 0
fetch install.sh 0
want=$(awk '{ f = $2; sub(/^\*/, "", f); if (f == "install.sh") print $1 }' "$work/SHA256SUMS" | head -n 1)
[ -n "$want" ] || die "SHA256SUMS lists no install.sh"
got=$(sha256_of "$work/install.sh")
[ "$got" = "$want" ] || die "install.sh does not match SHA256SUMS (want $want, got $got); refusing to run it"

if fetch SHA256SUMS.sig 1; then
  verifier=""
  if pick_verifier; then
    ok=0
    for k in $VENDOR_KEYS; do
      if "$verifier" "$k" "$work/SHA256SUMS.sig" "$work/SHA256SUMS"; then ok=1; break; fi
    done
    [ "$ok" -eq 1 ] || die "SHA256SUMS.sig does not verify against the vendor key; refusing to run install.sh"
    say "  signature ok"
  elif [ "${SBO_REQUIRE_SIGNATURE:-0}" = 1 ]; then
    die "no Ed25519 verifier here (OpenSSL 3, Node or Python cryptography) and SBO_REQUIRE_SIGNATURE=1"
  else
    warn "no Ed25519 verifier here (OpenSSL 3, Node or Python cryptography); install.sh was checked against SHA256SUMS only"
  fi
elif [ "${SBO_REQUIRE_SIGNATURE:-0}" = 1 ]; then
  die "the release publishes no SHA256SUMS.sig and SBO_REQUIRE_SIGNATURE=1"
else
  warn "the release publishes no SHA256SUMS.sig; install.sh was checked against SHA256SUMS only"
fi

# install.sh asks its questions on the terminal; it never reads this
# script's standard input (under `curl | sh` that is the script itself).
in=/dev/null
if ( : </dev/tty ) 2>/dev/null; then in=/dev/tty; fi
set -- --connect ${team:+"$team"} "$@"
if [ -n "$from_dir" ]; then set -- "$@" --from-dir "$from_dir"; fi
if [ "${SBO_REQUIRE_SIGNATURE:-0}" = 1 ]; then set -- "$@" --require-signature; fi
rc=0
sh "$work/install.sh" "$@" <"$in" || rc=$?
exit "$rc"
