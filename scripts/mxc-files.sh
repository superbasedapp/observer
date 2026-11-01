#!/usr/bin/env bash
# scripts/mxc-files.sh: the MXC files of the Windows sandbox driver
# (terminals.sandbox.mxc, sandbox plan v2 sections 11.3 and 12.3, ledger
# SBX-BE-15; lane SBX-P6). Microsoft Execution Containers' mxc_ffi.dll and
# wxc-exec.exe are fetched by a pinned hash, checked file by file, signature
# checked on a Windows runner (scripts/mxc-authenticode.ps1), and bundled
# beside observer.exe (bin/mxc/) only in the Windows artifacts of the
# distros that compile the driver. The node never downloads them: the
# helper checks the same hashes (compiled into internal/sandboxmxc) before
# anything is loaded or run.
#
#   scripts/mxc-files.sh fetch <dir>             download the pinned package, check it, extract the files
#   scripts/mxc-files.sh verify <dir>            check every file in <dir> against its pin
#   scripts/mxc-files.sh compiles <distro>       exit 0 when <distro> compiles the driver
#   scripts/mxc-files.sh bundle <dir> <bin-dir>  verify, then copy the files and the manifest into <bin-dir>/mxc
#   scripts/mxc-files.sh manifest <dir> [check]  write <dir>/mxc-manifest.json (the 12.3 entry)
#   scripts/mxc-files.sh stage <artifact> <stage> copy an edition artifact's mxc/ (when it has one) into an
#                                                archive stage and print its member names, one per line
#   scripts/mxc-files.sh sign-input <dir>        verify, write the manifest (Authenticode required) and print the
#                                                signing input of `vendorsign sandboxnative` (lane SBX-P3D); signs nothing
#
# The pins below must equal internal/sandboxmxc.ManifestX64
# (TestManifestMatchesReleaseScript). A pin left empty is "owed": every
# command that would bundle refuses, so a release can never ship an
# unpinned file.
set -euo pipefail

MXC_UPSTREAM="npm:@microsoft/mxc-sdk"
MXC_VERSION="1.0.1"
MXC_PKG_URL="https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.1.tgz"
MXC_PKG_SHA256="416d9607c9d4652395d95c3d9c5f5605f1f2f845da1a63228bee41b7392cef49"
MXC_SIGNER="Microsoft Corporation"
# name|path in the package|sha256|size
MXC_FILES=(
  "mxc_ffi.dll|package/bin/x64/mxc_ffi.dll|bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c|6123320"
  "wxc-exec.exe|package/bin/x64/wxc-exec.exe|090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a|12152632"
)
# The component that compiles the driver.
MXC_COMPONENT="terminals.sandbox.mxc"

die() { echo "mxc-files: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

size_of() { wc -c <"$1" | tr -d ' '; }

pins_complete() {
  [ -n "$MXC_PKG_URL" ] && [ -n "$MXC_PKG_SHA256" ] || return 1
  local f name path sum size
  for f in "${MXC_FILES[@]}"; do
    IFS='|' read -r name path sum size <<<"$f"
    [ -n "$name" ] && [ -n "$path" ] && [ ${#sum} -eq 64 ] && [ -n "$size" ] || return 1
  done
}

cmd_verify() {
  local dir="$1" f name path sum size got
  pins_complete || die "the MXC pins are owed; nothing is bundled without them"
  for f in "${MXC_FILES[@]}"; do
    IFS='|' read -r name path sum size <<<"$f"
    [ -f "$dir/$name" ] && [ ! -L "$dir/$name" ] || die "$name is missing from $dir (or is a link)"
    got=$(sha256_of "$dir/$name")
    [ "$got" = "$sum" ] || die "$name: sha256 $got does not match the pin $sum"
    [ "$(size_of "$dir/$name")" = "$size" ] || die "$name: size does not match the pin $size"
  done
  echo "mxc-files: every file matches its pin (MXC $MXC_VERSION)"
}

cmd_fetch() {
  local dir="$1" work f name path sum size
  pins_complete || die "the MXC pins are owed; refusing to fetch"
  mkdir -p "$dir"
  work=$(mktemp -d)
  if ! curl -fsSL --retry 3 --proto '=https' -o "$work/pkg.tgz" "$MXC_PKG_URL"; then
    rm -rf "$work"
    die "the package could not be downloaded"
  fi
  if [ "$(sha256_of "$work/pkg.tgz")" != "$MXC_PKG_SHA256" ]; then
    rm -rf "$work"
    die "the package does not match its pinned sha256"
  fi
  for f in "${MXC_FILES[@]}"; do
    IFS='|' read -r name path sum size <<<"$f"
    tar -xzf "$work/pkg.tgz" -C "$work" "$path"
    cp "$work/$path" "$dir/$name"
  done
  rm -rf "$work"
  cmd_verify "$dir"
}

cmd_compiles() {
  local distro="$1"
  go run ./cmd/sbo-components ids --distro "$distro" | grep -qx "$MXC_COMPONENT"
}

# json_escape quotes a string for the manifest.
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

cmd_manifest() {
  local dir="$1" check="${2:-}" auth="not_checked" f name path sum size first=1
  if [ -f "$dir/authenticode.txt" ]; then
    auth=$(tr -d '\r\n' <"$dir/authenticode.txt")
  fi
  if [ "$check" = check ] && [ "${auth%% *}" != valid ]; then
    die "the Authenticode check did not pass ($auth); nothing is bundled"
  fi
  {
    printf '{\n  "kind": "observer.mxc-files.v1",\n'
    printf '  "upstream": "%s",\n  "version": "%s",\n' "$(json_escape "$MXC_UPSTREAM")" "$MXC_VERSION"
    printf '  "package_url": "%s",\n  "package_sha256": "%s",\n' "$(json_escape "$MXC_PKG_URL")" "$MXC_PKG_SHA256"
    printf '  "signer": "%s",\n  "authenticode": "%s",\n  "files": [' "$(json_escape "$MXC_SIGNER")" "$(json_escape "$auth")"
    for f in "${MXC_FILES[@]}"; do
      IFS='|' read -r name path sum size <<<"$f"
      [ $first -eq 1 ] || printf ','
      first=0
      printf '\n    {"name": "%s", "package_path": "%s", "sha256": "%s", "size": %s}' "$name" "$path" "$sum" "$size"
    done
    printf '\n  ]\n}\n'
  } >"$dir/mxc-manifest.json"
  echo "mxc-files: wrote $dir/mxc-manifest.json"
}

# cmd_sign_input re-checks the pins and the Authenticode result and prints
# the input of the operator's signing step (sandbox.native_files, plan
# 12.3): the manifest path and the Go architecture. It never signs.
cmd_sign_input() {
  local dir="$1"
  cmd_verify "$dir" >/dev/null
  cmd_manifest "$dir" check >/dev/null
  echo "in=$dir/mxc-manifest.json"
  echo "arch=amd64"
}

cmd_bundle() {
  local dir="$1" bin="$2" f name path sum size
  cmd_verify "$dir"
  cmd_manifest "$dir" check
  mkdir -p "$bin/mxc"
  for f in "${MXC_FILES[@]}"; do
    IFS='|' read -r name path sum size <<<"$f"
    cp "$dir/$name" "$bin/mxc/$name"
  done
  cp "$dir/mxc-manifest.json" "$bin/mxc/mxc-manifest.json"
  cmd_verify "$bin/mxc"
  echo "mxc-files: bundled into $bin/mxc"
}

# cmd_stage copies an edition artifact's bundled files into the archive
# stage (nothing for an edition whose artifact carries none: a distro that
# omits the driver) and prints the archive members they add.
cmd_stage() {
  local art="$1" stage="$2" f name path sum size
  [ -d "$art/mxc" ] || return 0
  cmd_verify "$art/mxc" >&2
  mkdir -p "$stage/mxc"
  for f in "${MXC_FILES[@]}"; do
    IFS='|' read -r name path sum size <<<"$f"
    cp "$art/mxc/$name" "$stage/mxc/$name"
    echo "mxc/$name"
  done
  if [ -f "$art/mxc/mxc-manifest.json" ]; then
    cp "$art/mxc/mxc-manifest.json" "$stage/mxc/mxc-manifest.json"
    echo "mxc/mxc-manifest.json"
  fi
}

main() {
  local c="${1:-}"
  shift || true
  case "$c" in
    fetch) [ $# -eq 1 ] || die "usage: fetch <dir>"; cmd_fetch "$1" ;;
    verify) [ $# -eq 1 ] || die "usage: verify <dir>"; cmd_verify "$1" ;;
    compiles) [ $# -eq 1 ] || die "usage: compiles <distro>"; cmd_compiles "$1" ;;
    manifest) [ $# -ge 1 ] || die "usage: manifest <dir> [check]"; cmd_manifest "$@" ;;
    bundle) [ $# -eq 2 ] || die "usage: bundle <dir> <bin-dir>"; cmd_bundle "$1" "$2" ;;
    stage) [ $# -eq 2 ] || die "usage: stage <artifact> <stage>"; cmd_stage "$1" "$2" ;;
    sign-input) [ $# -eq 1 ] || die "usage: sign-input <dir>"; cmd_sign_input "$@" ;;
    *) die "usage: fetch|verify|compiles|manifest|bundle|stage|sign-input (see the header)" ;;
  esac
}

# Sourced by scripts/test-mxc-files.sh for its offline checks.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
