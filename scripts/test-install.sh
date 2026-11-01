#!/usr/bin/env bash
# test-install.sh: hermetic test for scripts/install.sh (T-729).
#
# Builds a fixture release directory for THIS host's platform (one archive
# per edition, SHA256SUMS, and <archive>.sig signed by scripts/vendorsign
# with a throwaway key) and runs install.sh --from-dir against it with a
# private HOME and prefix under a mktemp dir. No network: every case uses
# --from-dir, and the one network-shaped case must refuse before any
# download. Nothing outside the temp dir is touched.
#
# The packaged "observer" is a stub script that prints a version naming its
# edition and logs the verbs it is run with, so uninstall can be checked.
# Set OBSERVER_TEST_REAL_BINARY=<path to a real observer for this host> to
# package that binary as the developer edition instead (its --version must
# start with "observer version").
#
# Cases: dry run, default edition, every edition, checksum mismatch,
# missing SHA256SUMS line, edition absent from the release, bad signature,
# truncated signature, unsigned archive (warn; refused with
# --require-signature), each Ed25519 verifier this machine has (openssl 3,
# node, python cryptography, bc), the test-key guard, uninstall (incl. a
# failing `observer uninstall` keeping the binary unless --force), an
# npm-style symlink that must not be replaced, and in-place upgrades over a
# systemd unit (stood in for by OBSERVER_INSTALL_TEST_SYSTEMD; the stub logs
# the `observer service upgrade` the installer hands the restart to), and
# the macOS 13 floor (a sw_vers fixture via OBSERVER_INSTALL_TEST_SW_VERS).
#
# Usage: scripts/test-install.sh
#        INSTALL_SCRIPT=/path/to/install.sh scripts/test-install.sh
#        VENDORSIGN_BIN=/path/to/vendorsign scripts/test-install.sh
# Needs bash, tar, gzip and either VENDORSIGN_BIN or a Go toolchain (for
# `go run ./scripts/vendorsign`). Exit 0 = all cases pass.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${INSTALL_SCRIPT:-${REPO_ROOT}/scripts/install.sh}"

T="$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX")"
[[ -n "$T" && -d "$T" ]] || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$T"' EXIT

pass=0 fail=0 skip=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
skp() { skip=$((skip + 1)); echo "skip $*"; }

case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; *) echo "SKIP: unsupported host $(uname -s)"; exit 0 ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "SKIP: unsupported CPU"; exit 0 ;; esac
if [[ "$OS" == darwin && "$ARCH" == x64 && "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" == 1 ]]; then ARCH=arm64; fi
VER=v9.9.9-test.1

if [[ -n "${VENDORSIGN_BIN:-}" ]]; then
  VS=("$VENDORSIGN_BIN")
elif command -v go >/dev/null 2>&1; then
  VS=(go run "$REPO_ROOT/scripts/vendorsign")
else
  echo "SKIP: needs VENDORSIGN_BIN or a Go toolchain"; exit 0
fi

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# ---------------------------------------------------------------- fixture

mkdir -p "$T/key" "$T/rel" "$T/stage"
keyout="$( (cd "$REPO_ROOT" && "${VS[@]}" keygen -out "$T/key") 2>&1 )" || { echo "FAIL: vendorsign keygen: $keyout"; exit 1; }
PUB="$(printf '%s\n' "$keyout" | sed -n 's/^public key : //p')"
KEY="$T/key/vendor-signing-key.key"
[[ -n "$PUB" && -f "$KEY" ]] || { echo "FAIL: no test key ($keyout)"; exit 1; }

stub() { # stub <edition> <dir>
  mkdir -p "$2"
  cat >"$2/observer" <<EOF
#!/bin/sh
echo "\$*" >>"\$HOME/observer-calls.log"
case "\$1" in
  --version) echo "observer version ${VER#v} ($1 stub)" ;;
  uninstall) [ -z "\${FAKE_UNINSTALL_FAIL:-}" ] || { echo "stub uninstall: drifted config" >&2; exit 1; } ;;
esac
exit 0
EOF
  chmod 0755 "$2/observer"
  ln -sf observer "$2/superbased"
}

for ed in minimal developer managed full; do
  d="$T/stage/$ed"
  stub "$ed" "$d"
  if [[ "$ed" == developer && -n "${OBSERVER_TEST_REAL_BINARY:-}" ]]; then
    cp "$OBSERVER_TEST_REAL_BINARY" "$d/observer"; chmod 0755 "$d/observer"
  fi
  if [[ "$ed" == full ]]; then name="observer-$VER-$OS-$ARCH.tar.gz"; else name="observer-$VER-$ed-$OS-$ARCH.tar.gz"; fi
  tar -C "$d" -czf "$T/rel/$name" observer superbased
done
(cd "$T/rel" && for f in observer-*; do printf '%s  %s\n' "$(sha256 "$f")" "$f"; done > SHA256SUMS)
(cd "$REPO_ROOT" && "${VS[@]}" sign -key "$KEY" -allow-unpinned-key "$T"/rel/observer-*.tar.gz >/dev/null 2>&1) \
  || { echo "FAIL: vendorsign sign"; exit 1; }

# A copy of the release dir, for a case to break.
variant() { rm -rf "$T/v"; cp -R "$T/rel" "$T/v"; }

# run <label> <home> -- install.sh args... : output in $T/out, status in $rc
run() {
  local home="$1"; shift
  local extra=()
  mkdir -p "$home"
  if [[ -n "${OBSERVER_INSTALL_VERIFIER:-}" ]]; then extra+=("OBSERVER_INSTALL_VERIFIER=$OBSERVER_INSTALL_VERIFIER"); fi
  if [[ -n "${FAKE_UNINSTALL_FAIL:-}" ]]; then extra+=("FAKE_UNINSTALL_FAIL=$FAKE_UNINSTALL_FAIL"); fi
  if [[ -n "${OBSERVER_INSTALL_TEST_SYSTEMD:-}" ]]; then extra+=("OBSERVER_INSTALL_TEST_SYSTEMD=$OBSERVER_INSTALL_TEST_SYSTEMD"); fi
  if [[ -n "${OBSERVER_INSTALL_TEST_SW_VERS:-}" ]]; then extra+=("OBSERVER_INSTALL_TEST_SW_VERS=$OBSERVER_INSTALL_TEST_SW_VERS"); fi
  # A fixture /proc with no daemon (U4): a test never reads this host's
  # real processes.
  mkdir -p "$T/noproc"
  env -i PATH="$PATH" HOME="$home" TMPDIR="$T" OBSERVER_INSTALL_TEST_VENDOR_KEY="$PUB" OBSERVER_INSTALL_TEST_PROC="$T/noproc" \
    ${extra[@]+"${extra[@]}"} sh "$SCRIPT" "$@" >"$T/out" 2>&1 </dev/null
  rc=$?
}
has() { grep -q -- "$1" "$T/out"; }

# ------------------------------------------------------------------ cases

# 1. dry run: verifies, writes nothing.
run "$T/h1" --from-dir "$T/rel" --prefix "$T/p1" --dry-run
if [[ $rc -eq 0 ]] && has "dry run" && [[ ! -e "$T/p1" ]]; then ok "dry run verifies and writes nothing"; else bad "dry run (rc=$rc)"; cat "$T/out"; fi

# 2. default edition (non-interactive) is developer, signature verified.
run "$T/h2" --from-dir "$T/rel" --prefix "$T/p2"
if [[ $rc -eq 0 ]] && has "developer edition" && has "signature ok" && [[ -x "$T/p2/observer" && -L "$T/p2/superbased" ]] \
  && "$T/p2/observer" --version | grep -q '^observer version'; then
  ok "default edition is developer, checksum + signature verified, installed with the superbased alias"
else bad "default install (rc=$rc)"; cat "$T/out"; fi

# 3. every edition installs its own archive.
for ed in minimal managed full; do
  run "$T/h3$ed" --from-dir "$T/rel" --prefix "$T/p3$ed" --edition "$ed"
  if [[ $rc -eq 0 ]] && HOME="$T/h3$ed" "$T/p3$ed/observer" --version | grep -q "($ed stub)"; then ok "edition $ed installs its archive"
  else bad "edition $ed (rc=$rc)"; cat "$T/out"; fi
done
run "$T/h3x" --from-dir "$T/rel" --prefix "$T/p3x" --edition enterprise
if [[ $rc -ne 0 ]] && has "unknown edition"; then ok "unknown edition refused"; else bad "unknown edition (rc=$rc)"; fi

# 4. checksum mismatch: refused, nothing installed.
variant
printf 'x' >>"$T/v/observer-$VER-developer-$OS-$ARCH.tar.gz"
run "$T/h4" --from-dir "$T/v" --prefix "$T/p4" --edition developer
if [[ $rc -ne 0 ]] && has "checksum MISMATCH" && [[ ! -e "$T/p4/observer" ]]; then ok "checksum mismatch refused"; else bad "checksum mismatch (rc=$rc)"; cat "$T/out"; fi

# 5. the archive has no SHA256SUMS line.
variant
grep -v -- "-managed-" "$T/rel/SHA256SUMS" >"$T/v/SHA256SUMS"
run "$T/h5" --from-dir "$T/v" --prefix "$T/p5" --edition managed
if [[ $rc -ne 0 ]] && has "publishes no managed edition" && [[ ! -e "$T/p5/observer" ]]; then ok "edition missing from the release refused"; else bad "missing edition (rc=$rc)"; cat "$T/out"; fi

# 6. a signature from another file: refused.
variant
cp "$T/rel/observer-$VER-minimal-$OS-$ARCH.tar.gz.sig" "$T/v/observer-$VER-developer-$OS-$ARCH.tar.gz.sig"
run "$T/h6" --from-dir "$T/v" --prefix "$T/p6" --edition developer
if [[ $rc -ne 0 ]] && has "signature FAILED" && [[ ! -e "$T/p6/observer" ]]; then ok "wrong signature refused"; else bad "wrong signature (rc=$rc)"; cat "$T/out"; fi

# 7. a truncated signature: refused.
variant
head -c 63 "$T/rel/observer-$VER-developer-$OS-$ARCH.tar.gz.sig" >"$T/v/observer-$VER-developer-$OS-$ARCH.tar.gz.sig"
run "$T/h7" --from-dir "$T/v" --prefix "$T/p7" --edition developer
if [[ $rc -ne 0 ]] && has "not a 64-byte" && [[ ! -e "$T/p7/observer" ]]; then ok "truncated signature refused"; else bad "truncated signature (rc=$rc)"; cat "$T/out"; fi

# 8. unsigned: warns and installs; refused under --require-signature.
variant
rm -f "$T"/v/*.sig
run "$T/h8" --from-dir "$T/v" --prefix "$T/p8" --edition developer
if [[ $rc -eq 0 ]] && has "publishes no vendor signature" && [[ -x "$T/p8/observer" ]]; then ok "unsigned archive warns and installs"; else bad "unsigned (rc=$rc)"; cat "$T/out"; fi
run "$T/h8r" --from-dir "$T/v" --prefix "$T/p8r" --edition developer --require-signature
if [[ $rc -ne 0 ]] && [[ ! -e "$T/p8r/observer" ]]; then ok "unsigned archive refused with --require-signature"; else bad "require-signature (rc=$rc)"; cat "$T/out"; fi

# 9. each verifier this machine has, accepting the good signature and
#    refusing the wrong one.
variant
cp "$T/rel/observer-$VER-minimal-$OS-$ARCH.tar.gz.sig" "$T/v/observer-$VER-developer-$OS-$ARCH.tar.gz.sig"
for v in openssl node python bc; do
  OBSERVER_INSTALL_VERIFIER=$v run "$T/h9$v" --from-dir "$T/rel" --prefix "$T/p9$v" --edition developer --require-signature
  if [[ $rc -ne 0 ]] && has "no Ed25519 verifier"; then skp "verifier $v: not usable on this machine"; continue; fi
  if [[ $rc -eq 0 ]] && has "checked with $v"; then
    OBSERVER_INSTALL_VERIFIER=$v run "$T/h9${v}b" --from-dir "$T/v" --prefix "$T/p9${v}b" --edition developer
    if [[ $rc -ne 0 ]] && has "signature FAILED"; then ok "verifier $v accepts the good signature and refuses the wrong one"
    else bad "verifier $v wrong signature (rc=$rc)"; cat "$T/out"; fi
  else bad "verifier $v good signature (rc=$rc)"; cat "$T/out"; fi
done

# 10. the test key is never honoured on the download path.
run "$T/h10" --version "$VER" --prefix "$T/p10" --dry-run
if [[ $rc -ne 0 ]] && has "honoured only with --from-dir"; then ok "test key refused without --from-dir (no download attempted)"; else bad "test key guard (rc=$rc)"; cat "$T/out"; fi

# 11. --version that the directory does not hold.
run "$T/h11" --from-dir "$T/rel" --prefix "$T/p11" --version v1.0.0
if [[ $rc -ne 0 ]] && [[ ! -e "$T/p11/observer" ]]; then ok "a version the source does not hold is refused"; else bad "wrong version (rc=$rc)"; fi

# 12. an npm-style symlink at the target is never replaced.
mkdir -p "$T/p12" && ln -s /nonexistent/npm/observer "$T/p12/observer"
run "$T/h12" --from-dir "$T/rel" --prefix "$T/p12" --edition developer
if [[ $rc -ne 0 ]] && [[ -L "$T/p12/observer" ]]; then ok "a symlinked observer (npm / pip) is not replaced"; else bad "symlink guard (rc=$rc)"; cat "$T/out"; fi

# 13. uninstall: runs `observer uninstall --all`, removes binary + alias.
#     (A real binary does not write the stub's call log, so with
#     OBSERVER_TEST_REAL_BINARY only the removal is checked.)
run "$T/h2" --uninstall --prefix "$T/p2" --yes
called=1
if [[ -z "${OBSERVER_TEST_REAL_BINARY:-}" ]]; then grep -qx 'uninstall --all' "$T/h2/observer-calls.log" 2>/dev/null || called=0; fi
if [[ $rc -eq 0 ]] && [[ ! -e "$T/p2/observer" && ! -L "$T/p2/superbased" ]] && [[ $called -eq 1 ]]; then
  ok "uninstall runs observer uninstall --all, then removes the binary and alias"
else bad "uninstall (rc=$rc)"; cat "$T/out"; fi

# 14. uninstall when `observer uninstall` fails: kept, unless --force.
FAKE_UNINSTALL_FAIL=1 run "$T/h3minimal" --uninstall --prefix "$T/p3minimal" --yes
if [[ $rc -ne 0 ]] && [[ -x "$T/p3minimal/observer" ]] && has "binary was kept"; then ok "failed observer uninstall keeps the binary"; else bad "uninstall failure (rc=$rc)"; cat "$T/out"; fi
FAKE_UNINSTALL_FAIL=1 run "$T/h3minimal" --uninstall --prefix "$T/p3minimal" --yes --force
if [[ $rc -eq 0 ]] && [[ ! -e "$T/p3minimal/observer" ]]; then ok "--force removes the binary anyway"; else bad "uninstall --force (rc=$rc)"; cat "$T/out"; fi

# 15. uninstall --dry-run changes nothing; --purge is passed through.
run "$T/h3managed" --uninstall --prefix "$T/p3managed" --dry-run --purge
if [[ $rc -eq 0 ]] && [[ -x "$T/p3managed/observer" ]] && has "uninstall --all --purge"; then ok "uninstall dry run changes nothing and names --purge"; else bad "uninstall dry run (rc=$rc)"; cat "$T/out"; fi

# 15b. uninstall from a directory this user cannot write (T-744): refused
#      BEFORE anything changes (no `observer uninstall --all`, binary kept),
#      with the per-user commands and the one sudo delete printed. Root
#      writes anywhere, so the case is skipped there.
if [[ "$(id -u)" != 0 ]]; then
  run "$T/h15b" --from-dir "$T/rel" --prefix "$T/p15b" --edition developer
  chmod a-w "$T/p15b"
  : >"$T/h15b/observer-calls.log"
  run "$T/h15b" --uninstall --prefix "$T/p15b" --yes
  chmod u+w "$T/p15b"
  if [[ $rc -ne 0 ]] && has "sudo rm -f $T/p15b/observer" && has "nothing was changed" && [[ -x "$T/p15b/observer" ]] \
    && ! grep -q '^uninstall' "$T/h15b/observer-calls.log"; then
    ok "uninstall from an unwritable prefix changes nothing and prints the sudo command"
  else bad "unwritable-prefix uninstall (rc=$rc)"; cat "$T/out"; fi
else
  skp "unwritable-prefix uninstall: running as root"
fi

# 15d. the managed next step and the uninstall hint name the real commands
#      (T-746: rc.2 printed `observer org enroll` / `observer org unenroll`).
run "$T/h15d" --from-dir "$T/rel" --prefix "$T/p15d" --edition managed --no-service
if [[ $rc -eq 0 ]] && has "observer enroll --link" && ! has "observer org "; then ok "managed next step names observer enroll --link"
else bad "managed next step (rc=$rc)"; cat "$T/out"; fi
run "$T/h15d" --uninstall --prefix "$T/p15d" --dry-run
if [[ $rc -eq 0 ]] && has "leave it first: observer unenroll"; then ok "uninstall names observer unenroll"
else bad "uninstall leave hint (rc=$rc)"; cat "$T/out"; fi

# 15c. next steps never claim a proxy for the minimal edition (T-744).
run "$T/h15c" --from-dir "$T/rel" --prefix "$T/p15c" --edition minimal --no-service
if [[ $rc -eq 0 ]] && has "no proxy in this edition" && ! has "proxy + watcher"; then ok "minimal next steps claim no proxy"
else bad "minimal next steps (rc=$rc)"; cat "$T/out"; fi

# 15e. in-place upgrade over a running service (T-753). The rc.3 roll found
#      the installer replaced the binary underneath the running daemon and
#      offered the service again. Now: "Upgraded X -> Y", no second offer,
#      and the unit that runs this install is handed to the NEW binary's
#      `observer service upgrade` (which owns the route-off-first restart
#      decision; the installer never restarts anything). systemd is stood in
#      for by OBSERVER_INSTALL_TEST_SYSTEMD; the stub logs what it is run with.
old_stub() { # old_stub <prefix>: a previous install there
  mkdir -p "$1"
  # shellcheck disable=SC2016 # the stub expands these when it runs
  printf '#!/bin/sh\necho "$*" >>"$HOME/observer-calls.log"\n[ "$1" = --version ] && echo "observer version 9.9.8-old (developer stub)"\nexit 0\n' >"$1/observer"
  chmod 0755 "$1/observer"
}
unit_for() { # unit_for <home> <exec>: a user unit running <exec>
  mkdir -p "$1/.config/systemd/user"
  printf '[Unit]\nDescription=SuperBased Observer (proxy + watcher + dashboard)\n\n[Service]\nType=simple\nExecStart=%s start --config %s/cfg.toml\n' "$2" "$1" >"$1/.config/systemd/user/observer.service"
}
# 15e-15g need systemd, which the installer only drives on Linux
# (upgrade_service); elsewhere an upgrade leaves the service to the user.
if [[ "$(uname -s)" == Linux ]]; then
old_stub "$T/p15e"; mkdir -p "$T/h15e"; unit_for "$T/h15e" "$T/p15e/observer"
OBSERVER_INSTALL_TEST_SYSTEMD=1 run "$T/h15e" --from-dir "$T/rel" --prefix "$T/p15e" --edition developer
calls="$(cat "$T/h15e/observer-calls.log" 2>/dev/null)"
if [[ $rc -eq 0 ]] && has "Upgraded $T/p15e/observer: 9.9.8-old (developer stub) -> ${VER#v} (developer stub)" \
  && grep -qx 'service upgrade' <<<"$calls" && ! grep -q 'components add' <<<"$calls" \
  && ! has "Run Observer as a background service" && has "observer service status" && ! has "observer init"; then
  ok "upgrade over a running service: says Upgraded X -> Y, hands the unit to observer service upgrade, no second offer"
else bad "upgrade over a running service (rc=$rc; calls: $calls)"; cat "$T/out"; fi

# 15f. the unit runs ANOTHER install (an npm binary): left alone, and the
#      command that would move it is named.
old_stub "$T/p15f"; mkdir -p "$T/h15f"; unit_for "$T/h15f" "/usr/lib/node_modules/@superbased/observer-linux-x64/bin/observer"
OBSERVER_INSTALL_TEST_SYSTEMD=1 run "$T/h15f" --from-dir "$T/rel" --prefix "$T/p15f" --edition developer
if [[ $rc -eq 0 ]] && has "left alone" && has "service install --now" && ! grep -q '^service' "$T/h15f/observer-calls.log"; then
  ok "upgrade: a unit running another install is left alone"
else bad "upgrade with a foreign unit (rc=$rc)"; cat "$T/out"; fi

# 15g. --no-service on an upgrade leaves the unit untouched and names the command.
old_stub "$T/p15g"; mkdir -p "$T/h15g"; unit_for "$T/h15g" "$T/p15g/observer"
OBSERVER_INSTALL_TEST_SYSTEMD=1 run "$T/h15g" --from-dir "$T/rel" --prefix "$T/p15g" --edition developer --no-service
if [[ $rc -eq 0 ]] && has "service upgrade" && ! grep -q '^service' "$T/h15g/observer-calls.log"; then
  ok "upgrade with --no-service touches no unit and names observer service upgrade"
else bad "upgrade --no-service (rc=$rc)"; cat "$T/out"; fi
else
  skp "upgrade over a running service, a foreign unit, --no-service (systemd cases, Linux only)"
fi

# 15h. an upgrade without any service unit: no offer (non-interactive), the
#      upgrade line, and nothing run against systemd.
old_stub "$T/p15h"; mkdir -p "$T/h15h"
OBSERVER_INSTALL_TEST_SYSTEMD=1 run "$T/h15h" --from-dir "$T/rel" --prefix "$T/p15h" --edition minimal
if [[ $rc -eq 0 ]] && has "Upgraded" && ! grep -q '^service\|^components' "$T/h15h/observer-calls.log"; then
  ok "upgrade without a service unit runs nothing against systemd"
else bad "upgrade without a unit (rc=$rc)"; cat "$T/out"; fi

# 15i. a fresh install never claims an upgrade.
run "$T/h15i" --from-dir "$T/rel" --prefix "$T/p15i" --edition developer
if [[ $rc -eq 0 ]] && has "Installed $T/p15i/observer" && ! has "Upgraded" && has "is off by default; this turns it on\|observer start "; then
  ok "a fresh install says Installed, not Upgraded"
else bad "fresh install wording (rc=$rc)"; cat "$T/out"; fi

# 16. the interactive menu on a terminal (util-linux script(1) supplies
#     the pty): choosing 1 installs minimal; the service question, asked
#     only where systemd runs, is answered no.
if script --version 2>/dev/null | grep -q util-linux; then
  mkdir -p "$T/h16"
  mkdir -p "$T/noproc"
  printf '1\nn\n' | env -i PATH="$PATH" HOME="$T/h16" TMPDIR="$T" OBSERVER_INSTALL_TEST_VENDOR_KEY="$PUB" OBSERVER_INSTALL_TEST_PROC="$T/noproc" \
    script -qec "sh '$SCRIPT' --from-dir '$T/rel' --prefix '$T/p16'" /dev/null >"$T/out" 2>&1
  if has "Choose an edition" && HOME="$T/h16" "$T/p16/observer" --version 2>/dev/null | grep -q "(minimal stub)"; then
    ok "interactive menu: choice 1 installs the minimal edition"
  else bad "interactive menu"; cat "$T/out"; fi
else
  skp "interactive menu: util-linux script(1) not available"
fi

# ------------------------------------------------ another install (U4)
#
# A fake npm install (bin/observer -> lib/node_modules/@superbased/observer/
# bin/observer.js) and a fake pip console script are put on PATH, and a
# fixture /proc (OBSERVER_INSTALL_TEST_PROC) stands in for a daemon running
# another binary. The real /proc is never read by these cases.
NPMP="$T/npmglobal"
mkdir -p "$NPMP/lib/node_modules/@superbased/observer/bin" "$NPMP/bin"
printf '#!/bin/sh\necho "observer version 1.34.0"\n' >"$NPMP/lib/node_modules/@superbased/observer/bin/observer.js"
chmod 0755 "$NPMP/lib/node_modules/@superbased/observer/bin/observer.js"
ln -s ../lib/node_modules/@superbased/observer/bin/observer.js "$NPMP/bin/observer"
PIPV="$T/venv"
mkdir -p "$PIPV/bin"
printf '#!%s/bin/python3\n# -*- coding: utf-8 -*-\nimport sys\nfrom observer.__main__ import main\nif __name__ == "__main__":\n    sys.exit(main())\n' "$PIPV" >"$PIPV/bin/observer"
chmod 0755 "$PIPV/bin/observer"
EMPTYPROC="$T/emptyproc"; mkdir -p "$EMPTYPROC"
DPROC="$T/daemonproc"; mkdir -p "$DPROC/4242"
ln -s "$T/elsewhere/observer" "$DPROC/4242/exe"
printf '%s\0' "$T/elsewhere/observer" start >"$DPROC/4242/cmdline"

# runp <path prefix> <proc root> <home> -- install.sh args...: run() with an
# extra PATH entry and a fixture /proc.
runp() {
  local pathx="$1" procr="$2" home="$3"; shift 3
  mkdir -p "$home"
  env -i PATH="$pathx:$PATH" HOME="$home" TMPDIR="$T" OBSERVER_INSTALL_TEST_VENDOR_KEY="$PUB" \
    OBSERVER_INSTALL_TEST_PROC="$procr" sh "$SCRIPT" "$@" >"$T/out" 2>&1 </dev/null
  rc=$?
}

# 17. an npm install on PATH: refused without --force, names npm's own
#     upgrade command and --force, installs nothing.
runp "$NPMP/bin" "$EMPTYPROC" "$T/h17" --from-dir "$T/rel" --prefix "$T/p17"
if [[ $rc -ne 0 ]] && has "npm install: $NPMP/bin/observer" && has "npm install -g @superbased/observer@latest" \
  && has "--force" && [[ ! -e "$T/p17/observer" ]]; then
  ok "an npm install on PATH: explained, its upgrade command offered, nothing installed without --force"
else bad "npm install on PATH (rc=$rc)"; cat "$T/out"; fi

# 18. --force installs the second copy, defaulting to the existing
#     install's edition (npm ships the full build).
runp "$NPMP/bin" "$EMPTYPROC" "$T/h18" --from-dir "$T/rel" --prefix "$T/p18" --force
if [[ $rc -eq 0 ]] && has "second copy" && HOME="$T/h18" "$T/p18/observer" --version 2>/dev/null | grep -q "(full stub)"; then
  ok "--force installs a second copy with the existing install's edition (full)"
else bad "--force over npm (rc=$rc)"; cat "$T/out"; fi

# 19. a pip console script on PATH: the pip upgrade command is offered.
runp "$PIPV/bin" "$EMPTYPROC" "$T/h19" --from-dir "$T/rel" --prefix "$T/p19"
if [[ $rc -ne 0 ]] && has "pip install: $PIPV/bin/observer" && has "$PIPV/bin/python3 -m pip install --upgrade superbased-observer" \
  && [[ ! -e "$T/p19/observer" ]]; then
  ok "a pip install on PATH: its pip upgrade command is offered, nothing installed"
else bad "pip install on PATH (rc=$rc)"; cat "$T/out"; fi

# 20. a daemon running another binary: refused without --force; with
#     --force, installed but Next steps never start a second daemon.
runp "$T/none" "$DPROC" "$T/h20" --from-dir "$T/rel" --prefix "$T/p20" --edition developer
if [[ $rc -ne 0 ]] && has "running daemon: pid 4242" && [[ ! -e "$T/p20/observer" ]]; then
  ok "a running daemon from another install blocks a second install without --force"
else bad "running daemon guard (rc=$rc)"; cat "$T/out"; fi
runp "$T/none" "$DPROC" "$T/h20b" --from-dir "$T/rel" --prefix "$T/p20b" --edition developer --force
if [[ $rc -eq 0 ]] && [[ -x "$T/p20b/observer" ]] && has "A daemon from another install is running (pid 4242)" \
  && ! has "  observer start " && ! grep -q 'service install' "$T/h20b/observer-calls.log" 2>/dev/null; then
  ok "with --force beside a running daemon: no service offer and no \`observer start\` step"
else bad "next steps beside a running daemon (rc=$rc)"; cat "$T/out"; fi

# 21. --dry-run with an npm install on PATH: reports and stops, status 0.
runp "$NPMP/bin" "$EMPTYPROC" "$T/h21" --from-dir "$T/rel" --prefix "$T/p21" --dry-run
if [[ $rc -eq 0 ]] && has "a real run would stop here" && [[ ! -e "$T/p21" ]]; then
  ok "dry run with an npm install: reports and changes nothing"
else bad "dry run over npm (rc=$rc)"; cat "$T/out"; fi

# 22. on a terminal the menu defaults to keeping the existing install.
if script --version 2>/dev/null | grep -q util-linux; then
  mkdir -p "$T/h22"
  printf '\n' | env -i PATH="$NPMP/bin:$PATH" HOME="$T/h22" TMPDIR="$T" OBSERVER_INSTALL_TEST_VENDOR_KEY="$PUB" \
    OBSERVER_INSTALL_TEST_PROC="$EMPTYPROC" script -qec "sh '$SCRIPT' --from-dir '$T/rel' --prefix '$T/p22'" /dev/null >"$T/out" 2>&1
  if has "install a second copy at" && has "Nothing was installed" && [[ ! -e "$T/p22/observer" ]]; then
    ok "interactive: the default answer keeps the existing install"
  else bad "interactive other-install menu"; cat "$T/out"; fi
else
  skp "interactive other-install menu: util-linux script(1) not available"
fi

# 23. the macOS 13 floor (P-206): a sw_vers fixture stands in for the Mac's
# version on any host. 12.7 and an unreadable version are refused before
# anything is installed, naming v1.36.0; 13.0 and 15.1 install.
swvers() { # swvers <name> <version, or empty for unreadable>
  local f="$T/swvers-$1"
  if [[ -n "$2" ]]; then printf '#!/bin/sh\necho %s\n' "$2" >"$f"; else printf '#!/bin/sh\nexit 1\n' >"$f"; fi
  chmod 0755 "$f"; printf '%s' "$f"
}
OBSERVER_INSTALL_TEST_SW_VERS="$(swvers 12 12.7)" run "$T/h23a" --from-dir "$T/rel" --prefix "$T/p23a"
if [[ $rc -ne 0 ]] && has "needs macOS 13 Ventura or later" && has "runs macOS 12.7" && has "v1.36.0 is the last release for macOS 12" \
  && [[ ! -e "$T/p23a" ]]; then
  ok "macOS 12.7 is refused, naming v1.36.0, and nothing is installed"
else bad "macOS 12.7 floor (rc=$rc)"; cat "$T/out"; fi
OBSERVER_INSTALL_TEST_SW_VERS="$(swvers none "")" run "$T/h23b" --from-dir "$T/rel" --prefix "$T/p23b"
if [[ $rc -ne 0 ]] && has "could not read the macOS version" && has "macOS 13 Ventura or later" && [[ ! -e "$T/p23b" ]]; then
  ok "an unreadable macOS version is refused with a plain message"
else bad "unreadable macOS version (rc=$rc)"; cat "$T/out"; fi
for v in 13.0 15.1; do
  OBSERVER_INSTALL_TEST_SW_VERS="$(swvers "$v" "$v")" run "$T/h23-$v" --from-dir "$T/rel" --prefix "$T/p23-$v" --edition developer
  if [[ $rc -eq 0 ]] && [[ -x "$T/p23-$v/observer" ]] && ! has "needs macOS 13"; then
    ok "macOS $v is accepted"
  else bad "macOS $v floor (rc=$rc)"; cat "$T/out"; fi
done

echo
echo "install.sh: $pass passed, $fail failed, $skip skipped"
[[ $fail -eq 0 ]]
