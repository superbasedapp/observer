#!/usr/bin/env bash
# Publish path of Observer's default sandbox image (sandbox plan v2 section
# 12.3, ledger SBX-IMG-1, lane SBX-P3D). It takes build.sh's output and does
# everything short of the release key:
#   1. checks the OCI layout still carries the digest and image ids in the
#      descriptor build.sh wrote (a rebuilt or changed layout is refused:
#      sandbox_image_digest_mismatch) and that the descriptor's repository is
#      under --registry;
#   2. pushes the layout by digest with the digest preserved, using the
#      pinned skopeo (its version is checked and recorded);
#   3. reads the pushed manifest back and checks its sha256 is the digest;
#   4. runs the signing seam `vendorsign sandboximage -from-build -key FILE`.
# With no key file it stops at the named seam sandbox_image_signing_key_missing
# (exit 3) after the push: the descriptor and SBOM stay unsigned and no node
# accepts them. --dry-run does every check but neither pushes nor signs.
# The registry is a required argument; none is baked in (operator decision).
#
# Usage:
#   deploy/sandbox-image/publish.sh --registry REG [--out DIR] [--dry-run]
#       [--key FILE --manifest-version N [--epoch N] [--valid-days N]
#        [--revoke SHA256]... [--allow-unpinned-key]]
# Environment: SKOPEO (the push tool, default skopeo), VENDORSIGN (a built
# vendorsign binary; default `go run ./scripts/vendorsign`).
# Exit: 0 done, 2 bad arguments or tool, 3 the signing seam (no key),
#       4 sandbox_image_digest_mismatch, 1 any other failure.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# The pinned push tool. --preserve-digests needs skopeo 1.6 or newer; the
# pin is exact so the record names what pushed the bytes.
skopeo_version="1.16.1"

registry=""
out="$root/dist/sandbox-image"
dry_run=0
key=""
manifest_version=""
epoch=""
valid_days=""
allow_unpinned=0
revoke=()

die() { echo "publish.sh: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
	case "$1" in
	--registry) registry="${2:-}"; shift 2 ;;
	--out) out="${2:-}"; shift 2 ;;
	--dry-run) dry_run=1; shift ;;
	--key) key="${2:-}"; shift 2 ;;
	--manifest-version) manifest_version="${2:-}"; shift 2 ;;
	--epoch) epoch="${2:-}"; shift 2 ;;
	--valid-days) valid_days="${2:-}"; shift 2 ;;
	--revoke) revoke+=("${2:-}"); shift 2 ;;
	--allow-unpinned-key) allow_unpinned=1; shift ;;
	-h|--help) sed -n '2,26p' "$0"; exit 0 ;;
	*) die "unknown argument $1" ;;
	esac
done

[ -n "$registry" ] || die "--registry is required (none is baked in)"
[[ "$registry" =~ ^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)*$ ]] || die "--registry is not a registry name: $registry"
oci="$out/image.oci.tar"
[ -f "$oci" ] || die "no build output: $oci (run build.sh first)"
[ -f "$out/sandbox.image/sandbox-image.json" ] || die "no descriptor under $out/sandbox.image (run build.sh first)"
if [ -n "$manifest_version" ] && ! [[ "$manifest_version" =~ ^[1-9][0-9]*$ ]]; then
	die "--manifest-version must be a positive integer"
fi
if [ -n "$key" ]; then
	[ -f "$key" ] || die "--key names no file"
	[ -n "$manifest_version" ] || die "--key needs --manifest-version"
fi
for r in "${revoke[@]+"${revoke[@]}"}"; do
	[[ "$r" =~ ^(sha256:)?[a-f0-9]{64}$ ]] || die "--revoke wants a sha256 digest, got $r"
done

if [ -n "${VENDORSIGN:-}" ]; then
	vendorsign=("$VENDORSIGN")
else
	vendorsign=(go run "$root/scripts/vendorsign")
fi
skopeo="${SKOPEO:-skopeo}"
command -v "$skopeo" >/dev/null 2>&1 || die "the push tool $skopeo is not installed (pinned: skopeo $skopeo_version)"
got="$("$skopeo" --version 2>/dev/null || true)"
[ "$got" = "skopeo version $skopeo_version" ] || die "the push tool reports \"$got\", pinned skopeo $skopeo_version"

# Step 1: the reproducibility and registry check (no key: check only).
if ! facts="$("${vendorsign[@]}" sandboximage -from-build -oci "$oci" -out "$out" -registry "$registry" 2>&1)"; then
	echo "$facts" >&2
	if grep -q sandbox_image_digest_mismatch <<<"$facts"; then
		echo "publish.sh: sandbox_image_digest_mismatch: the layout is not the one build.sh described; rebuild and rerun" >&2
		exit 4
	fi
	exit 1
fi
repository="$(sed -n 's/^repository=//p' <<<"$facts")"
digest="$(sed -n 's/^digest=//p' <<<"$facts")"
version="$(sed -n 's/^version=//p' <<<"$facts")"
[ -n "$repository" ] && [ -n "$digest" ] && [ -n "$version" ] || { echo "$facts" >&2; die "vendorsign printed no repository, digest and version"; }

push=("$skopeo" copy --all --preserve-digests "oci-archive:$oci" "docker://$repository:$version")
readback=("$skopeo" inspect --raw "docker://$repository@$digest")
sign=("${vendorsign[@]}" sandboximage -from-build -oci "$oci" -out "$out" -registry "$registry" -key "$key" -manifest-version "$manifest_version")
[ -n "$epoch" ] && sign+=(-epoch "$epoch")
[ -n "$valid_days" ] && sign+=(-valid-days "$valid_days")
for r in "${revoke[@]+"${revoke[@]}"}"; do sign+=(-revoke "$r"); done
[ "$allow_unpinned" = 1 ] && sign+=(-allow-unpinned-key)

record="$out/publish-record.txt"
if [ "$dry_run" = 1 ]; then
	echo "publish.sh: dry run: $repository@$digest (version $version) matches the descriptor"
	echo "publish.sh: would push: ${push[*]}"
	echo "publish.sh: would check: ${readback[*]}"
	if [ -n "$key" ]; then
		echo "publish.sh: would sign: vendorsign sandboximage -from-build ... -manifest-version $manifest_version"
	else
		echo "publish.sh: would stop at the signing seam sandbox_image_signing_key_missing (no --key)"
	fi
	exit 0
fi

# Step 2: push by digest, digest preserved.
"${push[@]}"
# Step 3: the registry serves the same bytes under the digest.
pulled="$("${readback[@]}" | sha256sum | cut -d' ' -f1)"
[ "sha256:$pulled" = "$digest" ] || { echo "publish.sh: the registry serves sha256:$pulled for $repository@$digest" >&2; exit 1; }
{
	echo "pushed=$repository@$digest"
	echo "version=$version"
	echo "tool=skopeo $skopeo_version"
	echo "at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$record"

# Step 4: the signing seam.
if [ -z "$key" ]; then
	echo "signed=no (sandbox_image_signing_key_missing)" >>"$record"
	echo "publish.sh: sandbox_image_signing_key_missing: pushed $repository@$digest; the manifest is unsigned and no node accepts it until the release step signs it with --key" >&2
	exit 3
fi
"${sign[@]}" >/dev/null
echo "signed=yes manifest_version=$manifest_version" >>"$record"
echo "publish.sh: pushed and signed $repository@$digest; publish $out/sandbox.image/{manifest.json,sandbox-image.json,sandbox-image.spdx.json}"
