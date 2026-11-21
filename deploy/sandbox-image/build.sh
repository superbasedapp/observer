#!/usr/bin/env bash
# Reproducible build of Observer's default sandbox image (sandbox plan v2
# section 12.3, ledger SBX-IMG-1). It builds the recipe beside this script
# into an OCI layout tarball with every timestamp set to the recipe's last
# commit, exports the per-platform package lists, and runs `vendorsign
# sandboximage` to write the descriptor and the SPDX SBOM. It never signs
# and never pushes: signing with the vendor key and pushing with the digest
# preserved are the operator's release step. Two runs from the same commit
# and snapshot give the same digest.
#
# Usage:
#   deploy/sandbox-image/build.sh --version 1.0.0 --repository REPO \
#       --snapshot 20261020T000000Z [--min-version 1.0.0] \
#       [--platforms linux/amd64,linux/arm64] [--out DIR]
#   deploy/sandbox-image/build.sh --check   (static checks only, no build)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

version=""
min_version=""
repository=""
snapshot=""
platforms="linux/amd64,linux/arm64"
out="$root/dist/sandbox-image"
check_only=0

die() { echo "build.sh: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
	case "$1" in
	--version) version="${2:-}"; shift 2 ;;
	--min-version) min_version="${2:-}"; shift 2 ;;
	--repository) repository="${2:-}"; shift 2 ;;
	--snapshot) snapshot="${2:-}"; shift 2 ;;
	--platforms) platforms="${2:-}"; shift 2 ;;
	--out) out="${2:-}"; shift 2 ;;
	--check) check_only=1; shift ;;
	-h|--help) sed -n '2,17p' "$0"; exit 0 ;;
	*) die "unknown argument $1" ;;
	esac
done

# The base must be pinned by digest; a tag can move under the build.
base="$(sed -n 's/^ARG BASE=//p' "$here/Dockerfile")"
[[ "$base" =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$ ]] || die "the Dockerfile's BASE is not pinned by digest: $base"

# No agent CLI, ever (SBX-IMG-1): the same closed list the SBOM check uses.
agents='^(claude|claude-code|codex|gemini-cli|copilot|github-copilot-cli|aider|aider-chat|cursor|cursor-agent|opencode|goose|qwen-code|kimi-cli|crush|amp|droid|kiro-cli|cline)$'
if grep -v '^#' "$here/packages.txt" | grep -Eq "$agents"; then
	die "packages.txt names an agent CLI"
fi

if [ "$check_only" = 1 ]; then
	echo "build.sh: static checks passed (base $base)"
	exit 0
fi

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version MAJOR.MINOR.PATCH is required"
[ -n "$min_version" ] || min_version="$version"
[ -n "$repository" ] || die "--repository is required"
[[ "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "--snapshot YYYYMMDDTHHMMSSZ is required"
command -v docker >/dev/null || die "docker with buildx is required"
docker buildx version >/dev/null || die "docker buildx is required"

commit="$(git -C "$root" rev-parse HEAD)"
git -C "$root" diff --quiet HEAD -- "$here" || die "the recipe has uncommitted changes; build from a commit"
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct -- "$here")"
export SOURCE_DATE_EPOCH

mkdir -p "$out"
oci="$out/image.oci.tar"
pkgs="$out/packages"
rm -rf "$oci" "$pkgs"

common=(--platform "$platforms" --build-arg "DEBIAN_SNAPSHOT=$snapshot"
	--build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --provenance=false --sbom=false)
docker buildx build "${common[@]}" --target image \
	--output "type=oci,dest=$oci,rewrite-timestamp=true" "$here"
docker buildx build "${common[@]}" --target packages \
	--output "type=local,dest=$pkgs" "$here"

(cd "$root" && go run ./scripts/vendorsign sandboximage \
	-oci "$oci" -packages "$pkgs" -recipe "$here/Dockerfile" \
	-repository "$repository" -version "$version" -min-version "$min_version" \
	-commit "$commit" -base "$base" -source-date-epoch "$SOURCE_DATE_EPOCH" -out "$out")

echo "build.sh: built $oci; descriptor and SBOM in $out/sandbox.image (unsigned)"
