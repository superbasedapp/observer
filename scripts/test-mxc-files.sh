#!/usr/bin/env bash
# scripts/test-mxc-files.sh: offline checks of scripts/mxc-files.sh (lane
# SBX-P6): a file that does not match its pin, a missing file, owed pins
# and a failed signature check each refuse to bundle; good files bundle
# with their manifest. It swaps in pins of its own fake files, so it needs
# no network and no Windows. Run: scripts/test-mxc-files.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/mxc-files.sh
source "$here/mxc-files.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
expect_fail() { if ( "$@" ) >/dev/null 2>&1; then echo "FAIL: expected a refusal: $*"; fails=$((fails + 1)); else echo "ok: refused: $*"; fi; }
expect_ok() { if ( "$@" ) >/dev/null 2>&1; then echo "ok: $*"; else echo "FAIL: expected success: $*"; fails=$((fails + 1)); fi; }

mkdir -p "$work/files"
printf 'fake dll' >"$work/files/mxc_ffi.dll"
printf 'fake exe!' >"$work/files/wxc-exec.exe"
d1=$(sha256_of "$work/files/mxc_ffi.dll")
d2=$(sha256_of "$work/files/wxc-exec.exe")
MXC_FILES=("mxc_ffi.dll|package/bin/x64/mxc_ffi.dll|$d1|8" "wxc-exec.exe|package/bin/x64/wxc-exec.exe|$d2|9")

expect_ok cmd_verify "$work/files"
# No signature answer yet: bundling refuses.
expect_fail cmd_bundle "$work/files" "$work/bin0"
printf 'invalid NotSigned' >"$work/files/authenticode.txt"
expect_fail cmd_bundle "$work/files" "$work/bin1"
printf 'valid mxc_ffi.dll=AB wxc-exec.exe=CD' >"$work/files/authenticode.txt"
expect_ok cmd_bundle "$work/files" "$work/bin2"
[ -f "$work/bin2/mxc/mxc_ffi.dll" ] && [ -f "$work/bin2/mxc/wxc-exec.exe" ] && grep -q '"authenticode": "valid' "$work/bin2/mxc/mxc-manifest.json" \
  && echo "ok: bundled files and manifest" || { echo "FAIL: bundle layout"; fails=$((fails + 1)); }
# A tampered file refuses.
cp -r "$work/files" "$work/tampered"
printf 'fake dlX' >"$work/tampered/mxc_ffi.dll"
expect_fail cmd_bundle "$work/tampered" "$work/bin3"
# A missing file refuses.
cp -r "$work/files" "$work/missing"
rm "$work/missing/wxc-exec.exe"
expect_fail cmd_bundle "$work/missing" "$work/bin4"
# A link refuses.
cp -r "$work/files" "$work/linked"
rm "$work/linked/mxc_ffi.dll"
ln -s "$work/files/mxc_ffi.dll" "$work/linked/mxc_ffi.dll"
expect_fail cmd_verify "$work/linked"
# Owed pins refuse everything.
saved=("${MXC_FILES[@]}")
MXC_FILES=("mxc_ffi.dll|package/bin/x64/mxc_ffi.dll||8")
expect_fail cmd_verify "$work/files"
MXC_FILES=("${saved[@]}")
saved_pkg=$MXC_PKG_SHA256
MXC_PKG_SHA256=""
expect_fail cmd_fetch "$work/f2"
MXC_PKG_SHA256=$saved_pkg

# Edition staging: an artifact with bundled files adds its members, one
# without adds none, a tampered one refuses.
mkdir -p "$work/art-with/mxc" "$work/art-without" "$work/stage1" "$work/stage2"
cp "$work/bin2/mxc/"* "$work/art-with/mxc/"
members=$(cmd_stage "$work/art-with" "$work/stage1")
[ "$members" = "$(printf 'mxc/mxc_ffi.dll\nmxc/wxc-exec.exe\nmxc/mxc-manifest.json')" ] && [ -f "$work/stage1/mxc/wxc-exec.exe" ] \
  && echo "ok: staged an edition that compiles the driver" || { echo "FAIL: staging ($members)"; fails=$((fails + 1)); }
members=$(cmd_stage "$work/art-without" "$work/stage2")
[ -z "$members" ] && [ ! -d "$work/stage2/mxc" ] && echo "ok: nothing staged for an edition without the driver" || { echo "FAIL: staged files for an edition without the driver"; fails=$((fails + 1)); }
printf 'tampered' >"$work/art-with/mxc/wxc-exec.exe"
expect_fail cmd_stage "$work/art-with" "$work/stage3"

# The workflow wiring (edited, never dispatched): the MXC job fetches,
# checks the signature and writes the manifest on Windows; build_win32 and
# edition_build_win32 bundle only for win32 and only where the distro compiles
# the driver; the edition zips take the staged members.
if python3 -I - "$here/../.github/workflows/npm-release.yml" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
jobs = wf["jobs"]
m = jobs["mxc_files"]
assert m["runs-on"] == "windows-latest", m["runs-on"]
runs = " ".join(st.get("run", "") for st in m["steps"])
assert "mxc-files.sh fetch" in runs and "mxc-authenticode.ps1" in runs and "manifest mxc-stage check" in runs
up = [st for st in m["steps"] if st.get("uses", "").startswith("actions/upload-artifact")]
assert up and up[0]["with"]["name"] == "mxc-win32-x64"
# Only the win32 legs wait on the MXC job (SBX-P6 audit item 7, P-067).
for job, distro in (("build_win32", "full"), ("edition_build_win32", "${{ matrix.distro }}")):
    j = jobs[job]
    assert "mxc_files" in j["needs"], (job, j["needs"])
    steps = [st for st in j["steps"] if "mxc-files.sh compiles" in st.get("run", "")]
    assert len(steps) == 1, job
    st = steps[0]
    assert st["if"] == "matrix.target == 'win32-x64'", st["if"]
    assert "compiles " + distro in st["run"] and "mxc-files.sh bundle mxc-stage" in st["run"], st["run"]
pub = " ".join(st.get("run", "") for st in jobs["public_release"]["steps"])
assert 'mxc-files.sh stage "artifacts/edition-${d}-${target}"' in pub
assert '"${mxc_members[@]}"' in pub
PY
then echo "ok: the workflow wiring"; else echo "FAIL: the workflow wiring"; fails=$((fails + 1)); fi

# The distro decision: minimal omits the driver, the others compile it.
if command -v go >/dev/null 2>&1; then
  (cd "$here/.." && for d in developer managed full; do cmd_compiles "$d" || exit 1; done && ! cmd_compiles minimal) \
    && echo "ok: minimal omits the driver, developer, managed and full compile it" \
    || { echo "FAIL: the distro decision"; fails=$((fails + 1)); }
fi

if [ "$fails" -ne 0 ]; then
  echo "test-mxc-files: $fails failure(s)"
  exit 1
fi
echo "test-mxc-files: all checks passed"
