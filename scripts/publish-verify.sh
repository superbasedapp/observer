#!/usr/bin/env bash
# publish-verify.sh: check a release's files before .github/workflows/publish.yml
# hands any of them to a registry.
#
#   scripts/publish-verify.sh <dir> <file>...
#
# <dir> holds SHA256SUMS, SHA256SUMS.sig when the release was signed, and the
# files, named relative to <dir> (SHA256SUMS lists them by base name).
#   1. SHA256SUMS.sig is the raw 64-byte Ed25519 vendor signature over
#      SHA256SUMS (scripts/vendorsign). It must verify against one of the
#      keys scripts/install.sh accepts (its VENDOR_KEYS line, pinned to the
#      key compiled into the agent). A release built without the vendor
#      signing key has no SHA256SUMS.sig: the files are then checked against
#      SHA256SUMS alone, with a warning.
#   2. Every named file matches its SHA256SUMS line.
# Exits 0 when everything passes, 1 with ::error:: lines otherwise.
#
# The Ed25519 verifier is openssl (3.0 or newer) or node, whichever first
# verifies the RFC 8032 section 7.1 TEST 2 vector, the way scripts/install.sh
# picks one. PUBLISH_VERIFIER="openssl node" narrows or orders the list and
# INSTALL_SH names another installer to read the keys from (both for tests).
set -euo pipefail

fail() { echo "::error::$*"; exit 1; }

[ $# -ge 2 ] || { echo "usage: scripts/publish-verify.sh <dir> <file>..." >&2; exit 2; }
dir=$1
shift
here=$(cd "$(dirname "$0")" && pwd)
install_sh=${INSTALL_SH:-${here}/install.sh}

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT

# RFC 8032 section 7.1 TEST 2: the one-byte message 0x72 ("r"). Not TEST 1:
# its message is empty, and OpenSSL 3.5's `pkeyutl -rawin` refuses an empty
# input ("Could not allocate 0 bytes"), so TEST 1 would rule out a working
# openssl.
RFC_KEY="PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="
RFC_SIG="kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA=="

# verify_<x> <key base64> <sig file> <message file>: 0 when the signature
# verifies, 1 when it does not, 2 when the tool is missing.
verify_openssl() {
  command -v openssl >/dev/null 2>&1 || return 2
  # The 12-byte SPKI prefix of an Ed25519 key is exactly 16 base64
  # characters, so the key's base64 appends to it unchanged.
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$1" '-----END PUBLIC KEY-----' >"${tmp}/vk.pem"
  openssl pkeyutl -verify -pubin -inkey "${tmp}/vk.pem" -rawin -in "$3" -sigfile "$2" >/dev/null 2>&1
}

verify_node() {
  command -v node >/dev/null 2>&1 || return 2
  node -e '
    const c = require("crypto"), fs = require("fs");
    const a = process.argv.slice(1);
    if (typeof c.verify !== "function") process.exit(2);
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(a[0], "base64")]);
    const key = c.createPublicKey({ key: der, format: "der", type: "spki" });
    process.exit(c.verify(null, fs.readFileSync(a[2]), key, fs.readFileSync(a[1])) ? 0 : 1);
  ' "$1" "$2" "$3" >/dev/null 2>&1
}

# pick_verifier: the first verifier that passes the RFC 8032 vector.
pick_verifier() {
  printf '%s' "${RFC_SIG}" | base64 -d >"${tmp}/rfc.sig"
  printf 'r' >"${tmp}/rfc.msg"
  for v in ${PUBLISH_VERIFIER:-openssl node}; do
    case "${v}" in openssl|node) ;; *) continue ;; esac
    if "verify_${v}" "${RFC_KEY}" "${tmp}/rfc.sig" "${tmp}/rfc.msg"; then
      verifier=${v}
      return 0
    fi
  done
  return 1
}

[ -f "${dir}/SHA256SUMS" ] || fail "${dir} has no SHA256SUMS"

# 1. The vendor signature over SHA256SUMS.
if [ -f "${dir}/SHA256SUMS.sig" ]; then
  [ -f "${install_sh}" ] || fail "no ${install_sh} to read the vendor keys from"
  keys=$(sed -n 's/^VENDOR_KEYS="\(.*\)"$/\1/p' "${install_sh}")
  [ -n "${keys}" ] || fail "${install_sh} has no VENDOR_KEYS line"
  [ "$(wc -c <"${dir}/SHA256SUMS.sig" | tr -d ' ')" = 64 ] \
    || fail "SHA256SUMS.sig is not a 64-byte Ed25519 signature. Refusing to publish."
  verifier=""
  pick_verifier || fail "no working Ed25519 verifier (openssl 3 or node). Refusing to publish."
  ok=0
  for k in ${keys}; do
    if "verify_${verifier}" "${k}" "${dir}/SHA256SUMS.sig" "${dir}/SHA256SUMS"; then
      ok=1
      break
    fi
  done
  [ "${ok}" = 1 ] || fail "SHA256SUMS.sig does not verify against any vendor key in ${install_sh##*/}. Refusing to publish."
  echo "SHA256SUMS: vendor signature ok (${verifier})"
else
  echo "::warning::the release has no SHA256SUMS.sig (it was built without the vendor signing key), so its files are checked against SHA256SUMS only."
fi

# 2. Every file against its SHA256SUMS line.
for f in "$@"; do
  base=${f##*/}
  [ -f "${dir}/${f}" ] || fail "${f} was not downloaded"
  want=$(awk -v n="${base}" '{ x = $2; sub(/^\*/, "", x); if (x == n) print $1 }' "${dir}/SHA256SUMS" | head -n 1)
  [ -n "${want}" ] || fail "${base} is not listed in SHA256SUMS"
  got=$(sha256sum "${dir}/${f}" | awk '{ print $1 }')
  [ "${want}" = "${got}" ] || fail "checksum MISMATCH for ${base}: SHA256SUMS says ${want}, the file is ${got}"
  echo "ok  ${base}"
done
