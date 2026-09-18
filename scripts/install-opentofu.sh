#!/usr/bin/env bash
# install-opentofu.sh — installs a pinned OpenTofu release for Phase 2's
# `tofu fmt`/`tofu validate`/`tofu test` gates (deploy/modules/CONTRACT.md,
# docs/plans/enterprise-deployment-phase-2-implementation-plan-2026-09-18.md
# P2-D15: tested on OpenTofu, DR-15).
#
# This is a dev-tool / CI-runner install (like scripts/verify-price-
# snapshot.sh's release-gate role, not a customer-facing script): it
# downloads the linux_amd64 release asset (our dev containers and the
# `ci-private.yml` runners are the only callers today; a Windows/macOS
# contributor installs OpenTofu their own way, same as the memory note on
# `terraform v1.9.8` being a local dev-tool install) plus its SHA256SUMS
# from the pinned GitHub release, verifies the checksum, and installs the
# `tofu` binary to $PREFIX (default ~/.local/bin).
#
# Usage:
#   scripts/install-opentofu.sh            # install (skips if already
#                                           # installed at this version)
#   scripts/install-opentofu.sh --check    # print the installed version
#                                           # (exit 1 if tofu is not on PATH)
#
# PREFIX overrides the install directory. Never mutates the working tree;
# never shells out to git.
set -euo pipefail

OPENTOFU_VERSION="1.12.6"
PREFIX="${PREFIX:-$HOME/.local/bin}"

if [ "${1:-}" = "--check" ]; then
    if ! command -v tofu >/dev/null 2>&1; then
        echo "install-opentofu: tofu is not on PATH" >&2
        exit 1
    fi
    tofu version
    exit 0
fi

if command -v tofu >/dev/null 2>&1; then
    installed="$(tofu version -json 2>/dev/null | grep -o '"terraform_version":[[:space:]]*"[^"]*"' | sed -E 's/.*"([0-9.]+)"/\1/' || true)"
    if [ "$installed" = "$OPENTOFU_VERSION" ]; then
        echo "install-opentofu: tofu $OPENTOFU_VERSION already installed at $(command -v tofu)"
        exit 0
    fi
fi

OS="linux"
ARCH="amd64"
ASSET="tofu_${OPENTOFU_VERSION}_${OS}_${ARCH}.zip"
SUMS="tofu_${OPENTOFU_VERSION}_SHA256SUMS"
BASE_URL="https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "install-opentofu: downloading tofu ${OPENTOFU_VERSION} (${OS}/${ARCH})"
curl --fail --location --retry 3 --retry-connrefused --silent --show-error \
    -o "$workdir/$ASSET" "$BASE_URL/$ASSET"
curl --fail --location --retry 3 --retry-connrefused --silent --show-error \
    -o "$workdir/$SUMS" "$BASE_URL/$SUMS"

want_sum="$(grep " ${ASSET}\$" "$workdir/$SUMS" | awk '{print $1}')"
if [ -z "$want_sum" ]; then
    echo "install-opentofu: $ASSET not listed in $SUMS" >&2
    exit 1
fi
got_sum="$(sha256sum "$workdir/$ASSET" | awk '{print $1}')"
if [ "$got_sum" != "$want_sum" ]; then
    echo "install-opentofu: sha256 mismatch for $ASSET" >&2
    echo "  want: $want_sum" >&2
    echo "  got:  $got_sum" >&2
    exit 1
fi
echo "install-opentofu: sha256 verified ($got_sum)"

mkdir -p "$PREFIX"
unzip -o -q "$workdir/$ASSET" -d "$workdir/unzipped"
install -m 0755 "$workdir/unzipped/tofu" "$PREFIX/tofu"

echo "install-opentofu: installed $("$PREFIX/tofu" version | head -n 1) to $PREFIX/tofu"
if ! command -v tofu >/dev/null 2>&1; then
    echo "install-opentofu: $PREFIX is not on PATH - add it, e.g. export PATH=\"$PREFIX:\$PATH\"" >&2
fi
