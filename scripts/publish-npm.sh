#!/usr/bin/env bash
# publish-npm.sh: .github/workflows/publish.yml's npm publish, one kind of
# package at a time.
#
#   scripts/publish-npm.sh <dir> <observer|sdk> <dist-tag>
#
# <dir> holds plan.tsv (one line per package, in publish order, dependencies
# first: name, version, tarball, kind) and the tarballs, already checked by
# scripts/publish-verify.sh. Every package of the kind is published with
#   npm publish <tarball> --access public --tag <dist-tag> --provenance
# through npm trusted publishing: npm exchanges the job's OIDC identity for a
# short-lived publish credential, so no token is involved.
#
# Re-runs are safe. A version npm already has with the same bytes is skipped.
# A version npm already has with DIFFERENT bytes:
#   observer  fails, and nothing after it is published: a release's packages
#             go out once, so different bytes mean this is not the release
#             npm already has;
#   sdk       is skipped with a warning: the SDK version line rides every
#             binary release, so this means the SDK sources changed without
#             the SDK version being raised. npm keeps what it has.
# Under `latest`, a version older than the current `latest` fails before it is
# published: a re-run of an old release never moves `latest` back.
# Appends a table to $GITHUB_STEP_SUMMARY when that is set.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: scripts/publish-npm.sh <dir> <observer|sdk> <dist-tag>" >&2; exit 2; }
dir=$1 kind=$2 dist_tag=$3
case "${kind}" in
  observer|sdk) ;;
  *) echo "publish-npm.sh: kind ${kind}: want observer or sdk" >&2; exit 2 ;;
esac
[ -n "${dist_tag}" ] || { echo "publish-npm.sh: empty dist-tag" >&2; exit 2; }
cd "${dir}"
[ -f plan.tsv ] || { echo "::error::${dir} has no plan.tsv"; exit 1; }
summary=${GITHUB_STEP_SUMMARY:-/dev/null}

integrity() {
  node -e 'process.stdout.write("sha512-" + require("crypto").createHash("sha512").update(require("fs").readFileSync(process.argv[1])).digest("base64"))' "$1"
}
# newer A B: A is a strictly newer version than B.
newer() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]; }

{
  echo "## npm: the ${kind} packages"
  echo ""
  echo "| Package | Version | Result |"
  echo "|---|---|---|"
} >> "${summary}"
# The plan is read on fd 3, never stdin: npm reads stdin for an OTP prompt
# and would swallow the remaining lines.
while IFS=$'\t' read -r name version file k <&3; do
  [ "${k}" = "${kind}" ] || continue
  want=$(integrity "${file}")
  have=$(npm view "${name}@${version}" dist.integrity 2>/dev/null </dev/null || true)
  if [ -n "${have}" ]; then
    if [ "${have}" = "${want}" ]; then
      echo "::notice::${name}@${version} is already on npm with these exact bytes; skipped."
      echo "| \`${name}\` | ${version} | already on npm (same bytes) |" >> "${summary}"
      continue
    fi
    if [ "${kind}" = sdk ]; then
      echo "::warning::${name}@${version} is already on npm with DIFFERENT bytes (npm ${have}, release ${want}): the SDK sources changed without the SDK version being raised. npm keeps the version it has; raise the SDK version (sdk/python, sdk/typescript, sdk/widget and sdk/go together) to publish the change."
      echo "| \`${name}\` | ${version} | NOT published: npm has different bytes for this version |" >> "${summary}"
      continue
    fi
    echo "::error::${name}@${version} is already on npm with DIFFERENT bytes (npm ${have}, release ${want}). npm never replaces a version; nothing after it was published."
    exit 1
  fi
  if [ "${dist_tag}" = latest ]; then
    current=$(npm view "${name}" dist-tags.latest 2>/dev/null </dev/null || true)
    if [ -n "${current}" ] && newer "${current}" "${version}"; then
      echo "::error::${name}: latest is ${current}, newer than ${version}; publishing ${version} under latest would move it back. Nothing after it was published."
      exit 1
    fi
  fi
  npm publish "${file}" --access public --tag "${dist_tag}" --provenance </dev/null
  echo "| \`${name}\` | ${version} | published under \`${dist_tag}\` |" >> "${summary}"
done 3< plan.tsv
