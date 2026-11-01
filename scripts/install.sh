#!/bin/sh
# install.sh: install a SuperBased Observer edition on Linux or macOS.
#
#   sh install.sh [options]
#
# Options:
#   --edition <name>       minimal | developer | managed | full
#                          (default: a menu on a terminal, otherwise
#                          developer)
#   --version <v>          release to install, e.g. v1.36.0 or 1.36.0
#                          (default: latest, the newest FINAL release; a
#                          pre-release such as v1.36.0-rc.1 is installed
#                          only when named)
#   --prefix <dir>         where the binary goes (default: /usr/local/bin
#                          when root or when it is writable, otherwise
#                          ~/.local/bin; the installer never runs sudo)
#   --from-dir <dir>       install from a local directory holding the
#                          release assets (the archive, SHA256SUMS and
#                          <archive>.sig): air-gapped installs and tests,
#                          no network at all
#   --base-url <url>       an https mirror laid out like GitHub releases
#                          (<url>/download/<tag>/<asset>); needs --version
#   --require-signature    refuse unless the vendor signature is present
#                          and verified
#   --service              after installing, turn on integration.service
#                          and run `observer service install --now`
#                          (Linux with systemd: a user unit; macOS: a
#                          launchd agent that starts at sign-in)
#   --no-service           do not offer the service (on an upgrade: leave
#                          an existing service unit untouched)
#   --uninstall           stop the service unit if any, run `observer
#                          uninstall --all` (hook, MCP and proxy-route
#                          entries), then delete the binary; ~/.observer
#                          is kept
#   --purge                with --uninstall: also delete ~/.observer
#   --force                install a second copy even though another
#                          observer (npm, pip, another copy) is on PATH or
#                          a daemon from another install is running (the
#                          default: explain, offer the package manager's
#                          upgrade command and install nothing); with
#                          --uninstall: delete the binary even when
#                          `observer uninstall --all` reports a problem
#   --dry-run              say what would happen, change nothing
#   -y, --yes              ask nothing, take the defaults
#   -h, --help             this help
#
# Verification, before anything is written outside a temporary directory:
#   1. the archive's sha256 must equal its line in the release's
#      SHA256SUMS; a missing line or a mismatch is refused.
#   2. when the release publishes <archive>.sig (the raw 64-byte Ed25519
#      vendor signature over the archive bytes, the file the enterprise
#      update system verifies against internal/update/vendorkey.go), it
#      must verify against a vendor key compiled into this script; a bad
#      signature is always refused. An absent signature, or a machine with
#      no Ed25519 verifier (OpenSSL 3, Node 12+, Python cryptography or
#      bc), is a warning unless --require-signature.
#
# Upgrading in place (an observer already at <prefix>/observer): the installer
# says "Upgraded X -> Y" and does not offer the service again. A systemd unit
# that runs this install is refreshed by the new binary's `observer service
# upgrade`, which restarts the running daemon only when nothing routes through
# its proxy and otherwise prints the safe order; the daemon is the proxy, so it
# is never stopped under a live route (docs/daemon-restart-runbook.md). A
# foreground `observer start` still running the old binary is named, never
# signalled.
#
# No telemetry. The only hosts contacted are api.github.com (to resolve
# "latest") and github.com (the release assets), or your --base-url. It
# takes no token or credential. Uses curl, or wget when curl is absent.
set -eu

# The accepted vendor verification keys, newest first: the same values as
# internal/update/vendorkey.go (VendorPublicKeyV1, then the rotation slot
# VendorPublicKeyV0Previous while it is set). tests/invariant pins the two.
VENDOR_KEYS="npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="

DEFAULT_BASE_URL="https://github.com/superbasedapp/observer/releases"
LATEST_API_URL="https://api.github.com/repos/superbasedapp/observer/releases/latest"
DEFAULT_EDITION="developer"
# The launchd agent `observer service install` writes on macOS
# (internal/service/launchd.go LaunchdLabel).
LAUNCH_AGENT="$HOME/Library/LaunchAgents/app.superbased.observer.plist"

edition="" version="latest" prefix="" from_dir="" base_url=""
require_sig=0 service_choice="" uninstall=0 purge=0 force=0 dry_run=0 assume_yes=0

say() { printf '%s\n' "$*"; }
warn() { printf 'install.sh: WARNING: %s\n' "$*" >&2; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
usage() {
  if [ -f "$0" ]; then
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
  else
    say "usage: sh install.sh [--edition minimal|developer|managed|full] [--version vX.Y.Z] [--prefix DIR]"
    say "       [--from-dir DIR] [--base-url URL] [--require-signature] [--service|--no-service]"
    say "       [--uninstall [--purge] [--force]] [--dry-run] [--yes]"
  fi
}

need_arg() { [ "$2" -ge 2 ] || die "$1 needs a value (see --help)"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --edition) need_arg "$1" $#; edition="$2"; shift 2 ;;
    --edition=*) edition="${1#*=}"; shift ;;
    --version) need_arg "$1" $#; version="$2"; shift 2 ;;
    --version=*) version="${1#*=}"; shift ;;
    --prefix) need_arg "$1" $#; prefix="$2"; shift 2 ;;
    --prefix=*) prefix="${1#*=}"; shift ;;
    --from-dir) need_arg "$1" $#; from_dir="$2"; shift 2 ;;
    --from-dir=*) from_dir="${1#*=}"; shift ;;
    --base-url) need_arg "$1" $#; base_url="$2"; shift 2 ;;
    --base-url=*) base_url="${1#*=}"; shift ;;
    --require-signature) require_sig=1; shift ;;
    --service) service_choice=yes; shift ;;
    --no-service) service_choice=no; shift ;;
    --uninstall) uninstall=1; shift ;;
    --purge) purge=1; shift ;;
    --force) force=1; shift ;;
    --dry-run) dry_run=1; shift ;;
    -y|--yes) assume_yes=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------- helpers

have() { command -v "$1" >/dev/null 2>&1; }

# A question is asked only on a real terminal (read from /dev/tty, so
# `curl ... | sh` still works), never with --yes or --dry-run.
interactive() {
  [ "$assume_yes" -eq 0 ] || return 1
  [ "$dry_run" -eq 0 ] || return 1
  [ -t 1 ] || return 1
  ( : </dev/tty ) 2>/dev/null || return 1
  return 0
}

ask() { # ask <prompt> <default>: prints the answer
  printf '%s' "$1" >/dev/tty
  ask_reply=""
  IFS= read -r ask_reply </dev/tty || ask_reply=""
  if [ -z "$ask_reply" ]; then ask_reply="$2"; fi
  printf '%s\n' "$ask_reply"
}

yes_no() { # yes_no <prompt> <default y|n>: status 0 for yes
  yn=$(ask "$1" "$2")
  case "$yn" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

edition_line() {
  case "$1" in
    minimal) say "capture only: hooks, transcript watcher and the local dashboard; no proxy, terminals or self-update" ;;
    developer) say "a developer's own machine: proxy, dashboard, terminals, guard and every adapter (recommended)" ;;
    managed) say "a machine enrolled in an organization: org client and self-update on, local extras off" ;;
    full) say "everything compiled in: the build npm, PyPI and the VS Code extension ship" ;;
    *) return 1 ;;
  esac
}

valid_edition() { case "$1" in minimal|developer|managed|full) return 0 ;; *) return 1 ;; esac; }

valid_tag() { printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; }

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{ print $1 }'
  elif have shasum; then shasum -a 256 "$1" | awk '{ print $1 }'
  elif have openssl; then openssl dgst -sha256 "$1" | awk '{ print $NF }'
  else die "no sha256 tool found (need sha256sum, shasum or openssl)"
  fi
}

sha512_stdin() {
  if have sha512sum; then sha512sum | awk '{ print $1 }'
  elif have shasum; then shasum -a 512 | awk '{ print $1 }'
  elif have openssl; then openssl dgst -sha512 | awk '{ print $NF }'
  else return 1
  fi
}

b64d() { # base64 text on stdin, bytes on stdout
  if have base64 && base64 -d </dev/null >/dev/null 2>&1; then base64 -d
  elif have base64 && base64 -D </dev/null >/dev/null 2>&1; then base64 -D
  elif have openssl; then openssl base64 -d -A
  else return 1
  fi
}

file_size() { wc -c <"$1" | tr -d ' '; }

# download <url> <out>: fails on any HTTP error.
download() {
  case "$1" in https://*) ;; *) die "refusing a non-https URL: $1" ;; esac
  if have curl; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
  elif have wget; then
    wget -q --https-only -O "$2" "$1"
  else
    die "need curl or wget to download (or use --from-dir)"
  fi
}

# fetch_optional <url> <out>: 0 present, 1 absent (HTTP 404), 2 error.
fetch_optional() {
  if have curl; then
    code=$(curl -sSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" -w '%{http_code}' "$1" 2>/dev/null) || code=000
    case "$code" in
      200) return 0 ;;
      404) rm -f "$2"; return 1 ;;
      *) rm -f "$2"; return 2 ;;
    esac
  fi
  wget -q --https-only -O "$2" "$1" && return 0
  wrc=$?
  rm -f "$2"
  # wget exit 8 is "the server answered with an error" (the 404 case).
  if [ "$wrc" -eq 8 ]; then return 1; fi
  return 2
}

# get_asset <name> <out>: copy from --from-dir, or download.
get_asset() {
  if [ -n "$from_dir" ]; then
    [ -f "$from_dir/$1" ] || return 1
    cp "$from_dir/$1" "$2"
  else
    download "$asset_base/$1" "$2"
  fi
}

# get_optional <name> <out>: 0 present, 1 absent, 2 error.
get_optional() {
  if [ -n "$from_dir" ]; then
    [ -f "$from_dir/$1" ] || return 1
    cp "$from_dir/$1" "$2"
    return 0
  fi
  fetch_optional "$asset_base/$1" "$2"
}

# --------------------------------------------------- Ed25519 verification
#
# The vendor signature is the raw 64-byte Ed25519 signature over the whole
# archive (scripts/vendorsign/sign.go). Four verifiers are tried in order;
# each must first verify the RFC 8032 section 7.1 TEST 1 vector (empty
# message) before it is trusted with the real check.

RFC_KEY="11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
RFC_SIG="5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc+bRr0lv18FlbviRlUUFDjnoQCw=="

verify_openssl() { # verify_<x> <key base64> <sig file> <message file>
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

# hex_le <file>: the little-endian integer a file's bytes encode, as
# uppercase big-endian hex (what bc reads under ibase=16).
hex_le() {
  od -An -v -tx1 "$1" | tr -d ' \n' | hex_rev
}

hex_rev() { # hex text on stdin, byte-reversed uppercase hex on stdout
  awk '{ s = ""; for (i = length($0) - 1; i >= 1; i -= 2) s = s substr($0, i, 2); if (s == "") s = "0"; print toupper(s) }'
}

# verify_bc: RFC 8032 verification in bc arithmetic, the cofactorless
# check Go's crypto/ed25519 makes ([S]B == R + [k]A with k = SHA-512(R ||
# A || M) mod L, S < L). Needs only bc, od, awk, dd and a sha512 tool.
verify_bc() {
  have bc || return 2
  printf '%s' "$1" | b64d >"$work/bk.bin" 2>/dev/null || return 2
  [ "$(file_size "$work/bk.bin")" = 32 ] || return 1
  [ "$(file_size "$2")" = 64 ] || return 1
  dd if="$2" of="$work/br.bin" bs=32 count=1 2>/dev/null || return 2
  dd if="$2" of="$work/bs.bin" bs=32 skip=1 count=1 2>/dev/null || return 2
  bc_h=$(cat "$work/br.bin" "$work/bk.bin" "$3" | sha512_stdin) || return 2
  [ -n "$bc_h" ] || return 2
  bc_h=$(printf '%s\n' "$bc_h" | hex_rev)
  bc_a=$(hex_le "$work/bk.bin")
  bc_r=$(hex_le "$work/br.bin")
  bc_s=$(hex_le "$work/bs.bin")
  bc_out=$(bc <<EOF
scale=0
p=2^255-19
q=2^252+27742317777372353535851937790883648493
define md(a) {
  auto r
  r=a%p
  if (r<0) r=r+p
  return (r)
}
define pw(b,e,m) {
  auto r
  r=1
  b=b%m
  while (e>0) {
    if (e%2==1) r=(r*b)%m
    b=(b*b)%m
    e=e/2
  }
  return (r)
}
d=md(-121665*pw(121666,p-2,p))
sm=pw(2,(p-1)/4,p)
define ad(x1,y1,z1,t1,x2,y2,z2,t2) {
  auto a,b,c,e,f,g,h,k
  a=md((y1-x1)*(y2-x2))
  b=md((y1+x1)*(y2+x2))
  c=md(2*t1*t2*d)
  k=md(2*z1*z2)
  e=b-a
  f=k-c
  g=k+c
  h=b+a
  ox=md(e*f)
  oy=md(g*h)
  oz=md(f*g)
  ot=md(e*h)
  return (0)
}
define ml(s,x,y,z,t) {
  auto ax,ay,az,at,u
  ax=0
  ay=1
  az=1
  at=0
  while (s>0) {
    if (s%2==1) {
      u=ad(ax,ay,az,at,x,y,z,t)
      ax=ox
      ay=oy
      az=oz
      at=ot
    }
    u=ad(x,y,z,t,x,y,z,t)
    x=ox
    y=oy
    z=oz
    t=ot
    s=s/2
  }
  ox=ax
  oy=ay
  oz=az
  ot=at
  return (0)
}
define rc(y,sg) {
  auto w,x
  if (y>=p) return (-1)
  w=md((y*y-1)*pw(md(d*y*y+1),p-2,p))
  if (w==0) {
    if (sg==1) return (-1)
    return (0)
  }
  x=pw(w,(p+3)/8,p)
  if (md(x*x-w)!=0) x=md(x*sm)
  if (md(x*x-w)!=0) return (-1)
  if (x%2!=sg) x=p-x
  return (x)
}
bx=15112221349535400772501151409588531511454012693041857206046113283949847762202
by=46316835694926478169428394003475163141307993866256225615783033603165251855960
ibase=16
ka=$bc_a
kr=$bc_r
ks=$bc_s
kh=$bc_h
ibase=A
ok=1
tp=2^255
asg=ka/tp
ay=ka%tp
rsg=kr/tp
ry=kr%tp
if (ks>=q) ok=0
axx=rc(ay,asg)
if (axx<0) ok=0
rxx=rc(ry,rsg)
if (rxx<0) ok=0
if (ok==1) {
  hh=kh%q
  u=ml(ks,bx,by,1,md(bx*by))
  sx=ox
  sy=oy
  sz=oz
  u=ml(hh,axx,ay,1,md(axx*ay))
  u=ad(rxx,ry,1,md(rxx*ry),ox,oy,oz,ot)
  if (md(sx*oz-ox*sz)!=0) ok=0
  if (md(sy*oz-oy*sz)!=0) ok=0
}
ok
EOF
) || return 2
  # shellcheck disable=SC1003 # a backslash in the tr set, not an escaped quote
  [ "$(printf '%s' "$bc_out" | tr -d ' \n\\')" = 1 ]
}

# pick_verifier: the first verifier that passes the RFC 8032 vector.
# OBSERVER_INSTALL_VERIFIER="<openssl|node|python|bc>..." narrows the
# list (tests use it to exercise each verifier).
pick_verifier() {
  printf '%s' "$RFC_SIG" | b64d >"$work/rfc.sig" 2>/dev/null || return 1
  : >"$work/rfc.msg"
  for v in ${OBSERVER_INSTALL_VERIFIER:-openssl node python bc}; do
    case "$v" in openssl|node|python|bc) ;; *) continue ;; esac
    if "verify_$v" "$RFC_KEY" "$work/rfc.sig" "$work/rfc.msg"; then
      verifier="$v"
      return 0
    fi
  done
  return 1
}

# ------------------------------------------------------------- platform

detect_platform() {
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    MINGW*|MSYS*|CYGWIN*) die "this is Windows: use install.ps1 (PowerShell) instead" ;;
    *) die "unsupported OS $(uname -s): Observer ships for Linux, macOS and Windows" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=x64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported CPU $(uname -m): Observer ships for x86_64 and arm64" ;;
  esac
  # An Apple Silicon Mac running this shell under Rosetta reports x86_64;
  # install the native build.
  if [ "$os" = darwin ] && [ "$arch" = x64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
    arch=arm64
  fi
  check_macos_floor
}

# macos_version: the macOS product version (13.0, 15.1, ...). The hermetic
# tests stand in a fixture command for sw_vers with
# OBSERVER_INSTALL_TEST_SW_VERS (honoured only with --from-dir, like every
# other test hook); it prints the version, or nothing and fails to stand in
# for a version that cannot be read.
macos_version() {
  if [ -n "${OBSERVER_INSTALL_TEST_SW_VERS:-}" ] && [ -n "$from_dir" ]; then
    "$OBSERVER_INSTALL_TEST_SW_VERS" -productVersion 2>/dev/null
    return
  fi
  sw_vers -productVersion 2>/dev/null
}

# check_macos_floor: this release is built with Go 1.27, which needs macOS 13
# Ventura or later. A Mac below that is refused before anything is chosen or
# downloaded; v1.36.0 is the last release for macOS 12. Runs on macOS, and on
# any host when the tests stand in a sw_vers fixture.
check_macos_floor() {
  if [ "$os" != darwin ]; then
    [ -n "${OBSERVER_INSTALL_TEST_SW_VERS:-}" ] && [ -n "$from_dir" ] || return 0
  fi
  mv_ver=$(macos_version) || mv_ver=""
  mv_major=${mv_ver%%.*}
  case "$mv_major" in
    ''|*[!0-9]*) die "could not read the macOS version (sw_vers -productVersion). Observer needs macOS 13 Ventura or later; on macOS 12, stay on v1.36.0." ;;
  esac
  if [ "$mv_major" -lt 13 ]; then
    die "this release needs macOS 13 Ventura or later and this Mac runs macOS $mv_ver. v1.36.0 is the last release for macOS 12 (use the install.sh attached to v1.36.0), or upgrade macOS first."
  fi
}

default_prefix() {
  if [ "$(id -u)" = 0 ]; then
    say /usr/local/bin
  elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    say /usr/local/bin
  else
    say "$HOME/.local/bin"
  fi
}

on_path() {
  case ":$PATH:" in *":$1:"*) return 0 ;; *) return 1 ;; esac
}

# ------------------------------------------------------------- uninstall

do_uninstall() {
  if [ -n "$prefix" ]; then candidates="$prefix"; else candidates="/usr/local/bin $HOME/.local/bin"; fi
  target=""
  for dir in $candidates; do
    if [ -L "$dir/observer" ]; then
      warn "$dir/observer is a symlink (an npm or pip install?), not a binary this installer placed; skipped"
      continue
    fi
    if [ -f "$dir/observer" ]; then target="$dir"; break; fi
  done
  [ -n "$target" ] || die "no installer-placed observer binary in: $candidates (pass --prefix <dir>)"
  bin="$target/observer"
  unit_user="$HOME/.config/systemd/user/observer.service"
  unit_system="/etc/systemd/system/observer.service"
  # macOS: the launchd agent `observer service install` writes (T-920).
  if [ "$(uname -s)" = Darwin ]; then unit_user="$LAUNCH_AGENT"; fi

  say "Uninstall plan:"
  if [ -f "$unit_user" ]; then say "  - stop, disable and remove the user service unit ($bin service uninstall)"; fi
  if [ -f "$unit_system" ]; then say "  - stop, disable and remove the system service unit ($bin service uninstall --system)"; fi
  if [ "$purge" -eq 1 ]; then
    say "  - remove hook, MCP and proxy-route entries and DELETE ~/.observer ($bin uninstall --all --purge)"
  else
    say "  - remove hook, MCP and proxy-route entries ($bin uninstall --all); ~/.observer is kept"
  fi
  say "  - delete $bin"
  if [ -L "$target/superbased" ]; then say "  - delete the $target/superbased alias"; fi
  if [ -f "$target/antigravity-bridge.exe" ]; then say "  - delete $target/antigravity-bridge.exe"; fi
  say "If this machine is enrolled in an organization, leave it first: observer unenroll"
  say "Stop a running \`observer start\` first."

  # The binary's directory must be writable BEFORE anything changes: rc.2
  # stopped the service and removed every hook, then failed to delete a
  # root-owned /usr/local/bin/observer and left a half-uninstalled machine.
  # sudo is never run here, and `sudo sh install.sh --uninstall` would clean
  # root's HOME instead of yours, so the per-user steps run as you and only
  # the delete takes sudo.
  if [ "$(id -u)" != 0 ] && [ ! -w "$target" ]; then
    say ""
    say "$target is not writable by $(id -un 2>/dev/null || echo this user), so this script cannot delete $bin; nothing was changed."
    say "Run the per-user steps as yourself, then delete the binary with sudo:"
    if [ -f "$unit_user" ]; then say "  $bin service uninstall"; fi
    if [ "$purge" -eq 1 ]; then say "  $bin uninstall --all --purge"; else say "  $bin uninstall --all"; fi
    rm_line="sudo rm -f $bin"
    if [ -L "$target/superbased" ]; then rm_line="$rm_line $target/superbased"; fi
    if [ -f "$target/antigravity-bridge.exe" ]; then rm_line="$rm_line $target/antigravity-bridge.exe"; fi
    say "  $rm_line"
    if [ "$dry_run" -eq 1 ]; then say "(dry run: nothing changed)"; return 0; fi
    die "$target is not writable; follow the commands above (nothing was changed)"
  fi

  if [ "$dry_run" -eq 1 ]; then say "(dry run: nothing changed)"; return 0; fi
  if interactive; then
    if ! yes_no "Proceed? [y/N] " n; then say "Nothing changed."; return 0; fi
  fi

  if [ -f "$unit_user" ]; then "$bin" service uninstall || warn "observer service uninstall reported a problem"; fi
  if [ -f "$unit_system" ]; then
    if [ "$(id -u)" = 0 ]; then
      "$bin" service uninstall --system || warn "observer service uninstall --system reported a problem"
    else
      warn "a system unit exists at $unit_system; remove it with: sudo $bin service uninstall --system"
    fi
  fi
  if [ "$purge" -eq 1 ]; then set -- uninstall --all --purge; else set -- uninstall --all; fi
  if ! "$bin" "$@"; then
    if [ "$force" -eq 1 ]; then
      warn "\`observer $*\` failed; deleting the binary anyway (--force). Hook entries left behind fail until removed."
    else
      die "\`observer $*\` failed, so the binary was kept (deleting it would leave hook entries that point at a missing program). Fix the reported problem, or re-run with --force."
    fi
  fi
  rm -f "$bin"
  if [ -L "$target/superbased" ]; then rm -f "$target/superbased"; fi
  rm -f "$target/antigravity-bridge.exe"
  say "Removed $bin."
}

# --------------------------------------------------------------- install

# ------------------------------------------------- another install (U4)
#
# Lane FIX-UPGRADE U4 (D-590): installing over an npm or pip install used to
# put a SECOND copy in ~/.local/bin with one PATH warning, while the running
# daemon and the registered hooks kept the package-manager copy, and
# ~/.profile put ~/.local/bin first on PATH at the next login. Now the
# installer looks first, explains which copy wins, offers the package
# manager's own upgrade command, and installs a second copy only on an
# explicit menu answer or --force.

# resolve_link <path>: the path with every symlink followed (no readlink -f
# on older macOS).
resolve_link() {
  rl_p=$1 rl_n=0
  while [ -L "$rl_p" ] && [ "$rl_n" -lt 40 ]; do
    rl_t=$(readlink "$rl_p") || break
    case "$rl_t" in /*) rl_p=$rl_t ;; *) rl_p="$(dirname "$rl_p")/$rl_t" ;; esac
    rl_n=$((rl_n + 1))
  done
  real_path "$rl_p"
}

# install_kind <path>: npm, pip or archive for an `observer` found on PATH.
install_kind() {
  ik_r=$(resolve_link "$1")
  case "$ik_r" in
    */node_modules/@superbased/*) say npm; return 0 ;;
    */site-packages/observer/_bin/*|*/dist-packages/observer/_bin/*) say pip; return 0 ;;
  esac
  if [ -f "$ik_r" ] && [ "$(head -c 2 "$ik_r" 2>/dev/null)" = "#!" ] && grep -q 'observer\.__main__' "$ik_r" 2>/dev/null; then
    say pip
    return 0
  fi
  say archive
}

# upgrade_command <kind> <path>: the package manager's own upgrade command.
upgrade_command() {
  case "$1" in
    npm) say "npm install -g @superbased/observer@latest" ;;
    pip)
      case "$(resolve_link "$2")" in
        */pipx/*) say "pipx upgrade superbased-observer" ;;
        *)
          uc_py=$(head -n 1 "$(resolve_link "$2")" 2>/dev/null | sed -n 's/^#![[:space:]]*//p' | awk '{ print $1 }')
          say "${uc_py:-python3} -m pip install --upgrade superbased-observer"
          ;;
      esac
      ;;
    *) say "" ;;
  esac
}

# edition_of <path> <kind>: the edition an existing install runs. npm and
# pip ship the full build; an install.sh copy says so itself (components
# list --json, from v1.36.0); anything older or unreadable is unknown.
edition_of() {
  case "$2" in npm|pip) say full; return 0 ;; esac
  eo_d=$("$1" components list --json 2>/dev/null | sed -n 's/^  "distro": *"\([a-z]*\)".*/\1/p' | head -n 1)
  if valid_edition "$eo_d"; then say "$eo_d"; else say ""; fi
}

# running_daemons: "<pid> <executable>" for every `observer start` running
# from a binary other than <prefix>/observer (that one is this install's own
# upgrade, handled after it).
running_daemons() {
  rd_self=$(real_path "$prefix/observer")
  rd_root=/proc rd_walk=0
  [ "$os" = linux ] && rd_walk=1
  # Tests point it at a fixture /proc; honoured only with --from-dir, like
  # every other test hook. A fixture is walked like /proc on every OS, so a
  # test never reads the host's real processes (macOS has no /proc and
  # would otherwise fall through to ps).
  if [ -n "${OBSERVER_INSTALL_TEST_PROC:-}" ] && [ -n "$from_dir" ]; then rd_root=$OBSERVER_INSTALL_TEST_PROC rd_walk=1; fi
  if [ "$rd_walk" = 1 ]; then
    for rd_p in "$rd_root"/[0-9]*; do
      [ -e "$rd_p" ] || continue
      rd_exe=$(readlink "$rd_p/exe" 2>/dev/null) || continue
      rd_exe=${rd_exe% (deleted)}
      case "$(basename "$rd_exe")" in observer*) ;; *) continue ;; esac
      tr '\0' ' ' <"$rd_p/cmdline" 2>/dev/null | grep -q ' start' || continue
      [ "$rd_exe" = "$rd_self" ] && continue
      say "${rd_p##*/} $rd_exe"
    done
  elif have ps; then
    ps -axo pid=,command= 2>/dev/null | awk '{ c = $2; n = split(c, a, "/"); if (a[n] ~ /^observer/ && $3 == "start") print $1, c }' |
      while read -r rd_pid rd_cmd; do
        # ps shows argv[0] as typed: a foreground `observer start` run from
        # PATH is a bare name, which resolves through PATH (not the
        # installer's working directory) so this install's own daemon is
        # not reported as another install's.
        case "$rd_cmd" in */*) ;; *) rd_cmd=$(command -v "$rd_cmd" 2>/dev/null || printf '%s' "$rd_cmd") ;; esac
        [ "$(real_path "$rd_cmd")" = "$rd_self" ] && continue
        say "$rd_pid $rd_cmd"
      done
  fi
  return 0
}

# find_other_installs: sets other_found=1 and fills other_report (the lines to
# print), other_edition (the edition to default to) and other_daemons when an
# observer other than <prefix>/observer is on PATH or running.
find_other_installs() {
  other_found=0 other_report="" other_edition="" other_daemons="" fo_seen=""
  fo_self=$(resolve_link "$prefix/observer")
  fo_ifs=$IFS
  IFS=:
  for fo_d in $PATH; do
    IFS=$fo_ifs
    [ -n "$fo_d" ] || continue
    fo_c="$fo_d/observer"
    [ -e "$fo_c" ] || continue
    fo_r=$(resolve_link "$fo_c")
    [ "$fo_r" = "$fo_self" ] && continue
    case " $fo_seen " in *" $fo_r "*) continue ;; esac
    fo_seen="$fo_seen $fo_r"
    fo_k=$(install_kind "$fo_c")
    fo_v=$("$fo_c" --version 2>/dev/null | head -n 1)
    other_found=1
    other_report="$other_report
  $fo_k install: $fo_c (${fo_v:-version unknown})"
    fo_u=$(upgrade_command "$fo_k" "$fo_c")
    if [ -n "$fo_u" ]; then other_report="$other_report
      upgrade it in place with: $fo_u"; fi
    if [ -z "$other_edition" ]; then other_edition=$(edition_of "$fo_c" "$fo_k"); fi
  done
  IFS=$fo_ifs
  other_daemons=$(running_daemons)
  if [ -n "$other_daemons" ]; then
    other_found=1
    other_report="$other_report
$(printf '%s\n' "$other_daemons" | while read -r od_pid od_exe; do printf '  running daemon: pid %s (%s)\n' "$od_pid" "$od_exe"; done)"
  fi
}

# path_winner_note: which copy a shell runs now, and after the next login.
path_winner_note() {
  pw_now=$(command -v observer 2>/dev/null || true)
  say "  A shell runs the first \`observer\` on PATH: now ${pw_now:-none}."
  if ! on_path "$prefix"; then
    if [ "$prefix" = "$HOME/.local/bin" ] && grep -qs '\.local/bin' "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zprofile" 2>/dev/null; then
      say "  $prefix is not on PATH yet, but your login profile adds it (usually FIRST) at the next login,"
      say "  so the new copy would win then, while the running daemon and your hooks keep the other one."
    else
      say "  $prefix is not on PATH; the new copy would run only by its full path until you add it."
    fi
  fi
}

# gate_other_installs: decide what to do when another install was found.
# Table (first match wins): nothing found -> install; --force -> warn and
# install a second copy; a terminal -> ask (default: do not install, print
# the upgrade command); otherwise (--yes, a pipe, --dry-run) -> stop and
# name --force. Status 0 = go on installing, 1 = stop without an error.
gate_other_installs() {
  [ "$other_found" -eq 1 ] || return 0
  say "Observer is already installed on this machine:$other_report"
  path_winner_note
  if [ "$force" -eq 1 ]; then
    warn "installing a second copy at $prefix/observer anyway (--force)"
    return 0
  fi
  if interactive; then
    say "" >/dev/tty
    say "  1) keep the existing install and upgrade it with its own command (shown above)" >/dev/tty
    say "  2) install a second copy at $prefix/observer anyway" >/dev/tty
    say "  3) cancel" >/dev/tty
    go_pick=$(ask "Choice [1]: " 1)
    case "$go_pick" in
      2) return 0 ;;
      1|3|"") say "Nothing was installed."; return 1 ;;
      *) die "unknown choice '$go_pick'" ;;
    esac
  fi
  if [ "$dry_run" -eq 1 ]; then
    say "(dry run: a real run would stop here; pass --force to install a second copy anyway)"
    return 1
  fi
  die "not installing a second copy: upgrade the existing install with its own command above, or pass --force to install a second copy at $prefix/observer anyway"
}

choose_edition() {
  if [ -n "$edition" ]; then
    valid_edition "$edition" || die "unknown edition '$edition' (minimal, developer, managed or full)"
    return 0
  fi
  # U4: an existing install's edition is the default (npm and pip ship the
  # full build), so an upgrade does not silently change what runs.
  # An in-place upgrade asks the binary it replaces (only now, when no
  # --edition was given).
  if [ -z "$other_edition" ] && [ -f "$prefix/observer" ] && [ ! -L "$prefix/observer" ]; then
    other_edition=$(edition_of "$prefix/observer" archive)
  fi
  ce_default="${other_edition:-$DEFAULT_EDITION}"
  case "$ce_default" in minimal) ce_n=1 ;; managed) ce_n=3 ;; full) ce_n=4 ;; *) ce_n=2 ;; esac
  if interactive; then
    say "Choose an edition:" >/dev/tty
    n=1
    for e in minimal developer managed full; do
      printf '  %s) %-10s %s\n' "$n" "$e" "$(edition_line "$e")" >/dev/tty
      n=$((n + 1))
    done
    pick=$(ask "Edition [$ce_n, $ce_default]: " "$ce_n")
    case "$pick" in
      1|minimal) edition=minimal ;;
      2|developer) edition=developer ;;
      3|managed) edition=managed ;;
      4|full) edition=full ;;
      *) die "unknown choice '$pick'" ;;
    esac
  else
    edition="$ce_default"
  fi
}

# sums_versions <SHA256SUMS>: the release versions its agent archives name.
sums_versions() {
  awk '{
    f = $2; sub(/^\*/, "", f)
    if (f !~ /^observer-v[0-9]+\.[0-9]+\.[0-9]+.*\.(tar\.gz|zip)$/) next
    sub(/\.(tar\.gz|zip)$/, "", f)
    n = split(f, t, "-")
    m = n - 2
    if (t[m] ~ /^(minimal|developer|managed|full)$/) m--
    else if (m >= 4 && t[m - 1] == "custom" && length(t[m]) == 64) m -= 2
    v = t[2]
    for (i = 3; i <= m; i++) v = v "-" t[i]
    print v
  }' "$1" | sort -u
}

resolve_version() {
  case "$version" in
    latest|"") version=latest ;;
    v*) ;;
    [0-9]*) version="v$version" ;;
  esac
  if [ "$version" != latest ]; then
    valid_tag "$version" || die "not a release version: $version (want vX.Y.Z or vX.Y.Z-pre)"
    return 0
  fi
  if [ -n "$from_dir" ]; then
    found=$(sums_versions "$from_dir/SHA256SUMS")
    count=$(printf '%s\n' "$found" | grep -c . || true)
    if [ "$count" != 1 ]; then
      die "cannot tell which release $from_dir holds (found: $(printf '%s\n' "$found" | tr '\n' ' ')); pass --version"
    fi
    version="$found"
    return 0
  fi
  [ -z "$base_url" ] || die "--base-url needs an explicit --version"
  download "$LATEST_API_URL" "$work/latest.json" || die "could not resolve the latest release from $LATEST_API_URL (pass --version)"
  version=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$work/latest.json" | head -n 1)
  valid_tag "$version" || die "the latest-release lookup returned '$version', not a version (pass --version)"
}

asset_name() {
  if [ "$edition" = full ]; then
    say "observer-$version-$os-$arch.tar.gz"
  else
    say "observer-$version-$edition-$os-$arch.tar.gz"
  fi
}

# systemd_present: a systemd manager runs here. OBSERVER_INSTALL_TEST_SYSTEMD=1
# stands in for one in the hermetic tests (honoured only with --from-dir,
# like the test key); every systemctl call goes through the observer binary.
systemd_present() {
  if [ -n "${OBSERVER_INSTALL_TEST_SYSTEMD:-}" ] && [ -n "$from_dir" ]; then return 0; fi
  [ -d /run/systemd/system ]
}

# real_path <file>: the file's path with its directory's symlinks resolved
# (what the binary records in a unit it writes and what /proc shows).
real_path() {
  rp_dir=$(cd "$(dirname "$1")" 2>/dev/null && pwd -P) || { printf '%s\n' "$1"; return 0; }
  printf '%s/%s\n' "$rp_dir" "$(basename "$1")"
}

# unit_exec <unit file>: the program its ExecStart= line runs.
unit_exec() {
  sed -n 's/^ExecStart=//p' "$1" | head -n 1 | awk '{
    s = $0
    if (substr(s, 1, 1) == "\"") { s = substr(s, 2); i = index(s, "\""); if (i > 0) s = substr(s, 1, i - 1); print s }
    else print $1
  }'
}

# version_of <version line>: the version alone, from the first line the
# binary prints for --version.
version_of() { printf '%s\n' "$1" | sed 's/^observer version //'; }

# upgrade_service: on an upgrade, a systemd unit that already runs this
# install is refreshed by the NEW binary's `observer service upgrade` (T-753):
# it rewrites the unit for this binary with its arguments kept, refreshes its
# Description, and restarts the running daemon only when nothing routes
# through the proxy; otherwise it leaves the old daemon running and prints the
# safe order (the daemon IS the proxy; docs/daemon-restart-runbook.md). The
# installer never restarts anything itself. Status 0 when a unit was found
# (so the service is not offered again), 1 when there is none.
upgrade_service() {
  [ "$os" = linux ] || return 1
  systemd_present || return 1
  us_found=1
  us_self=$(real_path "$installed")
  for us_unit in "$HOME/.config/systemd/user/observer.service" /etc/systemd/system/observer.service; do
    [ -f "$us_unit" ] || continue
    us_found=0
    us_flag=""
    if [ "$us_unit" = /etc/systemd/system/observer.service ]; then us_flag=" --system"; fi
    us_ran=$(unit_exec "$us_unit")
    if [ -z "$us_ran" ] || [ "$(real_path "$us_ran")" != "$us_self" ]; then
      say "$us_unit runs ${us_ran:-another program}, not $installed: left alone. To move the service to this install: $installed service install --now$us_flag"
      continue
    fi
    if [ "$service_choice" = no ]; then
      say "$us_unit runs this install; with --no-service it was not touched. The running daemon keeps the previous binary until you run: $installed service upgrade$us_flag"
      continue
    fi
    if [ -n "$us_flag" ] && [ "$(id -u)" != 0 ]; then
      say "A system service ($us_unit) runs this install. Refresh it as root: sudo $installed service upgrade --system"
      continue
    fi
    say ""
    say "Refreshing the background service ($us_unit) for the new binary:"
    # shellcheck disable=SC2086 # us_flag is empty or one word
    if "$installed" service upgrade $us_flag; then
      service_done=1
    else
      warn "\`observer service upgrade$us_flag\` reported a problem; the previous daemon may still be running (docs/daemon-restart-runbook.md)"
    fi
  done
  return "$us_found"
}

# stale_daemons: pids of `observer start` processes still running the binary
# this install just replaced (Linux shows its executable as "(deleted)").
stale_daemons() {
  [ "$os" = linux ] || return 0
  sd_self="$(real_path "$installed") (deleted)"
  for sd_p in /proc/[0-9]*; do
    sd_exe=$(readlink "$sd_p/exe" 2>/dev/null) || continue
    [ "$sd_exe" = "$sd_self" ] || continue
    tr '\0' ' ' <"$sd_p/cmdline" 2>/dev/null | grep -q ' start' || continue
    printf '%s ' "${sd_p#/proc/}"
  done
}

offer_service() {
  # U4: never start a second daemon beside one from another install.
  [ -z "${other_daemons:-}" ] || return 0
  # integration.service is off by default in every edition
  # (docs/components.md), so the service is offered, never assumed, and it
  # is turned on through the binary's own component selection first.
  case "$os" in
    linux) systemd_present || return 0; os_kind="systemd user unit" ;;
    darwin)
      os_kind="launchd agent, starts when you sign in"
      # An agent that already runs this install keeps its arguments; the
      # running daemon moves to the new binary on its next restart.
      if [ -f "$LAUNCH_AGENT" ]; then
        say "A launchd agent ($LAUNCH_AGENT) already starts Observer. It runs the new binary after: $installed service restart"
        return 0
      fi
      ;;
    *) return 0 ;;
  esac
  if [ "$service_choice" = no ]; then return 0; fi
  if [ -z "$service_choice" ]; then
    interactive || return 0
    yes_no "Run Observer as a background service ($os_kind)? [y/N] " n || return 0
  fi
  if ! "$installed" components add integration.service --yes; then
    warn "could not turn on integration.service; the service was not installed"
    return 0
  fi
  if "$installed" service install --now; then
    service_done=1
  else
    warn "observer service install --now reported a problem"
  fi
}

verify_signature() {
  keys="$VENDOR_KEYS"
  if [ -n "${OBSERVER_INSTALL_TEST_VENDOR_KEY:-}" ]; then
    warn "verifying with the TEST key in OBSERVER_INSTALL_TEST_VENDOR_KEY, not the release keys"
    keys="$OBSERVER_INSTALL_TEST_VENDOR_KEY"
  fi
  sig_state=0
  get_optional "$asset.sig" "$work/$asset.sig" || sig_state=$?
  case "$sig_state" in
    0)
      [ "$(file_size "$work/$asset.sig")" = 64 ] || die "$asset.sig is not a 64-byte Ed25519 signature. Refusing to install."
      if pick_verifier; then
        sig_ok=0
        for k in $keys; do
          if "verify_$verifier" "$k" "$work/$asset.sig" "$work/$asset"; then sig_ok=1; break; fi
        done
        [ "$sig_ok" -eq 1 ] || die "vendor signature FAILED for $asset: it does not verify against any accepted vendor key. Refusing to install."
        say "  signature ok (vendor Ed25519, checked with $verifier)"
      elif [ "$require_sig" -eq 1 ]; then
        die "no Ed25519 verifier here (OpenSSL 3, Node 12+, Python cryptography or bc) and --require-signature was given"
      else
        warn "the vendor signature was not checked: no Ed25519 verifier here (OpenSSL 3, Node 12+, Python cryptography or bc). The sha256 matched."
      fi
      ;;
    1)
      [ "$require_sig" -eq 0 ] || die "$version publishes no vendor signature for $asset and --require-signature was given"
      warn "$version publishes no vendor signature for $asset; only the sha256 was checked"
      ;;
    *) die "could not fetch $asset.sig (network error). Re-run, or use --from-dir." ;;
  esac
}

do_install() {
  detect_platform
  if [ -z "$prefix" ]; then prefix=$(default_prefix); fi
  # U4: another observer on PATH (npm, pip, another copy) or a running
  # daemon from another binary is found and explained BEFORE anything is
  # chosen or downloaded.
  find_other_installs
  gate_other_installs || return 0
  choose_edition
  if [ -n "$base_url" ]; then
    case "$base_url" in https://*) ;; *) die "--base-url must be https" ;; esac
  fi
  if [ -n "${OBSERVER_INSTALL_TEST_VENDOR_KEY:-}" ] && [ -z "$from_dir" ]; then
    die "OBSERVER_INSTALL_TEST_VENDOR_KEY is honoured only with --from-dir"
  fi
  if [ -n "$from_dir" ]; then
    [ -d "$from_dir" ] || die "--from-dir: not a directory: $from_dir"
    [ -f "$from_dir/SHA256SUMS" ] || die "--from-dir: $from_dir has no SHA256SUMS"
  elif ! have curl && ! have wget; then
    die "need curl or wget to download (or use --from-dir)"
  fi
  have tar || die "need tar"
  resolve_version
  asset_base="${base_url:-$DEFAULT_BASE_URL}/download/$version"
  asset=$(asset_name)
  if [ -z "$prefix" ]; then prefix=$(default_prefix); fi

  say "SuperBased Observer $version, $edition edition"
  say "  edition   $(edition_line "$edition")"
  say "  platform  $os-$arch"
  say "  archive   $asset"
  if [ -n "$from_dir" ]; then say "  source    $from_dir"; else say "  source    $asset_base"; fi
  say "  install   $prefix/observer"

  get_asset SHA256SUMS "$work/SHA256SUMS" || die "could not get SHA256SUMS for $version"
  want=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == n) print $1 }' "$work/SHA256SUMS" | head -n 1)
  if [ -z "$want" ]; then
    if [ "$edition" != full ]; then
      die "release $version publishes no $edition edition for $os-$arch ($asset is not in its SHA256SUMS). Editions are published from v1.36.0; use --edition full for an older release."
    fi
    die "release $version has no $asset in its SHA256SUMS"
  fi

  if [ "$dry_run" -eq 1 ] && [ -z "$from_dir" ]; then
    say "(dry run: $asset is listed; it was not downloaded and nothing changed)"
    return 0
  fi

  get_asset "$asset" "$work/$asset" || die "could not get $asset"
  got=$(sha256_of "$work/$asset")
  if [ "$got" != "$want" ]; then
    die "checksum MISMATCH for $asset: SHA256SUMS says $want, the file is $got. Refusing to install."
  fi
  say "  sha256    ok"
  verify_signature

  mkdir -p "$work/x"
  members=$(tar -tzf "$work/$asset") || die "$asset is not a readable tar.gz"
  printf '%s\n' "$members" | grep -qx 'observer' || die "$asset has no observer member"
  tar -xzf "$work/$asset" -C "$work/x" observer
  if printf '%s\n' "$members" | grep -qx 'antigravity-bridge.exe'; then
    tar -xzf "$work/$asset" -C "$work/x" antigravity-bridge.exe
  fi
  if [ ! -f "$work/x/observer" ] || [ -L "$work/x/observer" ]; then
    die "$asset: observer is not a regular file"
  fi
  chmod 0755 "$work/x/observer"
  if ! reported=$("$work/x/observer" --version 2>&1); then
    die "the extracted binary does not run on this machine: $reported"
  fi
  reported=$(printf '%s\n' "$reported" | head -n 1)
  say "  binary    $reported"

  # An existing install this run replaces (an upgrade, T-753).
  previous=""
  if [ -f "$prefix/observer" ] && [ ! -L "$prefix/observer" ]; then
    previous=$("$prefix/observer" --version 2>/dev/null | head -n 1) || previous=""
    [ -n "$previous" ] || previous="observer version unknown"
    say "  current   $previous"
  fi

  if [ "$dry_run" -eq 1 ]; then
    say "(dry run: verified, nothing installed)"
    return 0
  fi

  mkdir -p "$prefix" 2>/dev/null || die "cannot create $prefix (pass --prefix <dir>, or run as root for /usr/local/bin)"
  [ -w "$prefix" ] || die "$prefix is not writable (pass --prefix \"\$HOME/.local/bin\", or run as root)"
  if [ -L "$prefix/observer" ] || { [ -e "$prefix/observer" ] && [ ! -f "$prefix/observer" ]; }; then
    die "$prefix/observer exists and is not a regular file (an npm or pip install?); refusing to replace it"
  fi
  cp "$work/x/observer" "$prefix/.observer.new.$$"
  chmod 0755 "$prefix/.observer.new.$$"
  mv -f "$prefix/.observer.new.$$" "$prefix/observer"
  if [ -L "$prefix/superbased" ] || [ ! -e "$prefix/superbased" ]; then
    ln -sf observer "$prefix/superbased"
  else
    warn "$prefix/superbased exists and is not an alias this installer made; left alone"
  fi
  if [ -f "$work/x/antigravity-bridge.exe" ]; then
    cp "$work/x/antigravity-bridge.exe" "$prefix/antigravity-bridge.exe"
  fi
  installed="$prefix/observer"
  say ""
  if [ -n "$previous" ]; then
    say "Upgraded $installed: $(version_of "$previous") -> $(version_of "$reported")."
  else
    say "Installed $installed ($reported)."
  fi

  if ! on_path "$prefix"; then
    warn "$prefix is not on your PATH; add it, e.g.: export PATH=\"$prefix:\$PATH\""
  else
    resolved=$(command -v observer 2>/dev/null || true)
    if [ -n "$resolved" ] && [ "$resolved" != "$installed" ]; then
      warn "\`observer\` on your PATH is $resolved, not $installed (an npm or pip install?); remove one so the shell runs the one you expect"
    fi
  fi

  service_done=0
  if [ -n "$previous" ]; then
    # An upgrade: a unit that already runs this install is refreshed (and
    # restarted only when that is safe), never offered a second time.
    upgrade_service || offer_service
    stale=$(stale_daemons)
    if [ -n "$stale" ]; then
      say ""
      say "\`observer start\` (pid ${stale% }) still runs the previous binary. The daemon is the proxy: restart it when no AI"
      say "session uses the proxy, with the proxy route off first (docs/daemon-restart-runbook.md)."
    fi
    say ""
    say "Your configuration and data in ~/.observer are unchanged."
    say "Next steps:"
    if [ "$service_done" -eq 1 ]; then
      say "  observer service status                # the background service"
    fi
    say "  observer components status             # what this edition runs"
    return 0
  fi
  # U4: a daemon from another install is running (only possible with
  # --force or menu choice 2). Never start a second daemon: no service offer,
  # and no `observer start` in Next steps.
  if [ -n "$other_daemons" ]; then
    say ""
    say "A daemon from another install is running ($(printf '%s\n' "$other_daemons" | awk '{ printf "%s%s", s, $1; s = ", " }' | sed 's/^/pid /')),"
    say "so no service was offered and nothing was started. To move to this copy: when no AI session uses the proxy, turn"
    say "the proxy route off, stop that daemon, then start this one (docs/daemon-restart-runbook.md)."
    say ""
    say "Next steps:"
    say "  $installed components status   # what this edition runs"
    return 0
  fi
  offer_service

  say ""
  say "Next steps:"
  if [ "$edition" = managed ]; then
    say "  observer enroll --link <enrolment link>  # join your organization"
  fi
  # What `observer start` runs: the minimal edition compiles the proxy out
  # (T-744), so it never claims one there.
  if [ "$edition" = minimal ]; then
    runs="watcher + dashboard (no proxy in this edition)"
    wires="hooks for your AI tools"
  else
    runs="proxy + watcher + dashboard"
    wires="hooks, MCP and the proxy route for your AI tools"
  fi
  say "  observer init                          # $wires"
  if [ "$service_done" -eq 1 ]; then
    say "  observer service status                # the background service is installed and running"
  elif [ "$os" = linux ] && systemd_present; then
    say "  observer start                         # $runs, in the foreground"
    say "  # or as a background service (integration.service is off by default; this turns it on):"
    say "  observer components add integration.service --yes && observer service install --now"
  else
    say "  observer start                         # $runs (http://localhost:8081)"
  fi
  say "  observer components status             # what this edition runs"
}

# ------------------------------------------------------------------ main

work=$(mktemp -d 2>/dev/null || mktemp -d -t observer-install)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT TERM

if [ "$uninstall" -eq 1 ]; then
  do_uninstall
else
  [ "$purge" -eq 0 ] || die "--purge applies only to --uninstall"
  do_install
fi
