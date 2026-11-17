#!/usr/bin/env bash
# gate-attestation.sh [<sha>]: does the ops gate attest this commit? (L-139)
#
# Prints attested=true or attested=false, and appends the same line to
# $GITHUB_OUTPUT when it is set. A workflow skips a job listed in
# scripts/ci/gate-coverage.tsv only on attested=true; everything else runs on
# GitHub as before. Any doubt answers false (no key in this tree, no
# attestation, a bad signature, another commit, a failed or partial gate), so
# a check is never skipped without a passing gate behind it. It never fails
# the job: the answer is false instead.
#
# The attestation is published by scripts/ci/publish-gate-attestation.sh as
# refs/gate-attestations/<sha>: a commit whose tree holds ci-attest.json and
# ci-attest.sig, signed on the ops VM by attest-sign.sh with the key whose
# public half is deploy/saas-ovh/ops/ci-attest.pub. The check needs only git,
# openssl and jq (all on GitHub's runners), and takes seconds.
set -uo pipefail

sha=${1:-${GITHUB_SHA:-}}
pub=${GATE_ATTEST_PUB:-deploy/saas-ovh/ops/ci-attest.pub}
min_units=${GATE_ATTEST_MIN_UNITS:-500}

answer() {
  echo "attested=$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "attested=$1" >>"$GITHUB_OUTPUT"; fi
  echo "gate-attestation: $2" >&2
  exit 0
}

[[ $sha =~ ^[0-9a-f]{40}$ ]] || answer false "no full commit sha given; every job runs here"
[ -s "$pub" ] || answer false "no $pub in this tree (the public repository, or before the key was made); every job runs here"
command -v openssl >/dev/null && command -v jq >/dev/null || answer false "openssl or jq missing; every job runs here"

ref="refs/gate-attestations/$sha"
git fetch --quiet --no-tags --depth=1 origin "+$ref:$ref" 2>/dev/null ||
  answer false "no attestation for $sha; every job runs here"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show "$ref:ci-attest.json" >"$tmp/a.json" 2>/dev/null && git show "$ref:ci-attest.sig" >"$tmp/a.sig" 2>/dev/null ||
  answer false "$ref lacks ci-attest.json or ci-attest.sig; every job runs here"
base64 -d <"$tmp/a.sig" >"$tmp/a.der" 2>/dev/null || answer false "the signature is not base64; every job runs here"
openssl dgst -sha256 -verify "$pub" -signature "$tmp/a.der" "$tmp/a.json" >/dev/null 2>&1 ||
  answer false "the attestation for $sha does not verify under $pub; every job runs here"
jq -e --arg sha "$sha" --argjson min "$min_units" '
  .version == 1 and .purpose == "sbo-ci-attest-v1" and .sha == $sha and
  .mode == "full" and .verdict == "GATE PASS" and .units_pass >= $min and
  (.signed_at | type == "string" and length > 0)' "$tmp/a.json" >/dev/null 2>&1 ||
  answer false "the attestation for $sha is not a passing full gate of this commit; every job runs here"
answer true "the ops gate passed $sha in full ($(jq -r '.units_pass' "$tmp/a.json") units, signed $(jq -r '.signed_at' "$tmp/a.json")); the jobs in scripts/ci/gate-coverage.tsv are skipped"
