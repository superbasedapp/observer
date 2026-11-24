#!/usr/bin/env bash
# sdk.sh - the one owner of the SDK build and test commands (plan W2-4, lane
# B4). The ops gate's sdk:* units (scripts/ci/gate-commands.tsv) and the
# release workflow (.github/workflows/npm-release.yml, job sdk_pack) both call
# it, so the gate tests exactly what the release builds.
#
#   scripts/ci/sdk.sh python
#       Tests sdk/python with the python3 on PATH (the gate puts one pinned
#       CPython per unit there, scripts/ci/gate-tools.tsv): a fresh venv, the
#       package installed from a copy of the source with its [test] extra
#       (and on Python 3.10+ its [test-instrument] extra, the frameworks the
#       offline instrument conformance scenarios drive), then pytest (the
#       package's own testpaths). On Python 3.10 to 3.13 a SECOND venv with
#       [test-instrument-crewai] runs the instrument tests again for the
#       CrewAI scenario: CrewAI pins openai < 3 and the OpenAI Agents SDK
#       needs openai >= 3, so the two cannot share one environment.
#   scripts/ci/sdk.sh node
#       Tests sdk/typescript with the node on PATH: npm ci, the typecheck
#       script and the test script (which builds first).
#   scripts/ci/sdk.sh java
#       Tests sdk/java with the java and mvn on PATH (Java 17+): mvn test
#       (BehaviourCasesTest runs every section of the shared case file and
#       fails when one has no Java runner), pointed at the copied contract.
#   scripts/ci/sdk.sh go
#       Tests sdk/go (module github.com/superbasedapp/observer/sdk/go) with
#       the go on PATH: gofmt (no unformatted file), go vet and go test -race
#       (the behaviour cases of sdk/contract and the package's own tests).
#       The module is separate from the repository root module, so the
#       product build never sees it.
#   scripts/ci/sdk.sh widget
#       Tests sdk/widget (@superbased/feedback-widget, review E-11) with the
#       node on PATH: npm ci, the typecheck script and the test script. The
#       widget releases with the SDKs, on the same version line.
#
#   Both test modes lay the copy out as the tree does (<work>/sdk/<package>
#   beside <work>/sdk/contract), so the tests that check the SDK against
#   sdk/contract run instead of skipping. Both get SUPERBASED_REPO_ROOT (the
#   read-only tree: the Go vocabulary sources, the docs some tests check);
#   node also gets SUPERBASED_CONTRACT_DIR.
#   scripts/ci/sdk.sh pack <outdir> [--version <x.y.z>]
#       Builds the release artifacts into <outdir>: the Python sdist and
#       wheel (python -m build) and the two npm tarballs (npm pack:
#       @superbased/sdk and @superbased/feedback-widget), checks that each
#       carries its licence, typing marker and entry points, and with
#       --version checks that every manifest names that version
#       (release.sh sdk-preflight passes the one it was given). Needs
#       python3 and node on PATH.
#
# Every mode works on a copy of the package in a temporary directory, never
# in the source tree: several gate units run at once on one worker and share
# the tree, and npm ci, pip and pytest all write next to the sources.
#
# The scripts the packages define (pytest's testpaths, npm's typecheck, test
# and build scripts) are called by name, so a package that changes how it
# tests or builds needs no change here.
set -euo pipefail

die() { echo "sdk.sh: $*" >&2; exit 1; }
log() { echo "sdk.sh: $*"; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
py_src="${root}/sdk/python"
ts_src="${root}/sdk/typescript"
java_src="${root}/sdk/java"
widget_src="${root}/sdk/widget"
go_src="${root}/sdk/go"
contract_src="${root}/sdk/contract"

# work: a private temporary directory, removed on exit.
work="$(mktemp -d "${TMPDIR:-/tmp}/sdkci.XXXXXX")"
trap 'rm -rf "${work}"' EXIT

# Quiet, reproducible tool output; no network prompts.
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PYTHONDONTWRITEBYTECODE=1
export npm_config_fund=false npm_config_audit=false npm_config_update_notifier=false

copy_pkg() { # copy_pkg <src> <dest>: the package without build outputs
  mkdir -p "$2"
  tar -C "$1" --exclude=node_modules --exclude=dist --exclude=build \
    --exclude='*.egg-info' --exclude=__pycache__ --exclude=.pytest_cache \
    -cf - . | tar -C "$2" -xf -
}

need() { command -v "$1" >/dev/null || die "$1 is not on PATH"; }

# copy_contract: sdk/contract beside the package copies, where the tests
# look for it (<package>/../contract).
copy_contract() { copy_pkg "${contract_src}" "${work}/sdk/contract"; }

# py_venv <dir> <extras>: a fresh venv with the package copy installed with
# <extras>. A regular (not editable) install: the tests import the installed
# package, which is what a user gets from the wheel.
py_venv() {
  python3 -m venv "$1"
  "$1/bin/python" -m pip install --quiet --upgrade pip
  "$1/bin/python" -m pip install --quiet "${work}/sdk/python[$2]"
  "$1/bin/python" -m pip check
}

test_python() {
  need python3
  log "python: $(python3 --version 2>&1) at $(command -v python3)"
  copy_pkg "${py_src}" "${work}/sdk/python"
  copy_contract
  local minor extras="test"
  minor="$(python3 -c 'import sys; print(sys.version_info[1] if sys.version_info[0] == 3 else 0)')"
  # The instrumentation frameworks' current releases need Python 3.10+
  # (docs/sdk/python/versioning.md); on 3.9 those scenarios skip.
  if (( minor >= 10 )); then extras="test,test-instrument"; fi
  py_venv "${work}/venv" "${extras}"
  # The repository files some tests read (the docs) are not in the copy.
  export SUPERBASED_REPO_ROOT="${root}"
  (cd "${work}/sdk/python" && "${work}/venv/bin/python" -m pytest -q -p no:cacheprovider)
  if (( minor >= 10 && minor <= 13 )); then
    log "python: CrewAI scenario in its own venv (CrewAI pins openai < 3)"
    py_venv "${work}/venv-crewai" "test,test-instrument-crewai"
    (cd "${work}/sdk/python" && "${work}/venv-crewai/bin/python" -m pytest -q -p no:cacheprovider tests/test_instrument.py)
  fi
}

test_node() {
  need node
  need npm
  log "node: $(node --version) at $(command -v node), npm $(npm --version)"
  copy_pkg "${ts_src}" "${work}/sdk/typescript"
  copy_contract
  (
    cd "${work}/sdk/typescript"
    export SUPERBASED_REPO_ROOT="${root}" SUPERBASED_CONTRACT_DIR="${work}/sdk/contract"
    npm ci --no-progress
    npm run --silent typecheck
    npm test
    # The example apps (sdk:e2e runs them) compile against the build too.
    if [[ -f examples/tsconfig.json ]]; then npx --no-install tsc -p examples/tsconfig.json --noEmit; fi
  )
}

test_java() {
  need java
  need mvn
  log "java: $(java -version 2>&1 | head -n1), $(mvn -v 2>/dev/null | head -n1)"
  copy_pkg "${java_src}" "${work}/sdk/java"
  rm -rf "${work}/sdk/java/target"
  copy_contract
  (
    cd "${work}/sdk/java"
    mvn -B -ntp test -Dsuperbased.contract.dir="${work}/sdk/contract"
  )
}

test_go() {
  need go
  log "go: $(go version) at $(command -v go)"
  copy_pkg "${go_src}" "${work}/sdk/go"
  copy_contract
  (
    cd "${work}/sdk/go"
    export SUPERBASED_CONTRACT_DIR="${work}/sdk/contract"
    local unformatted
    unformatted="$(gofmt -l .)"
    [[ -z "${unformatted}" ]] || die "go: gofmt would change: ${unformatted}"
    go vet ./...
    go test -race -count=1 ./...
  )
}

test_widget() {
  need node
  need npm
  log "widget: $(node --version) at $(command -v node), npm $(npm --version)"
  copy_pkg "${widget_src}" "${work}/sdk/widget"
  (
    cd "${work}/sdk/widget"
    npm ci --no-progress
    npm run --silent typecheck
    npm test
  )
}

# check_listing <archive listing file> <what> <required path>...
check_listing() {
  local list="$1" what="$2"; shift 2
  local p
  for p in "$@"; do
    grep -Eq "(^|/)${p}\$" "${list}" || die "${what} lacks ${p}"
  done
}

pack() {
  local out="" version=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="${2:-}"; shift 2 ;;
      -*) die "pack: unknown flag $1" ;;
      *) [[ -z "${out}" ]] || die "pack: one output directory"; out="$1"; shift ;;
    esac
  done
  [[ -n "${out}" ]] || die "pack: needs an output directory"
  need python3
  need node
  need npm
  mkdir -p "${out}"
  out="$(cd "${out}" && pwd)"

  local pyver tsver
  pyver="$(python3 -c 'import re,sys; m=re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"", open(sys.argv[1]).read()); print(m.group(1) if m else "")' "${py_src}/pyproject.toml")"
  tsver="$(node -p 'require(process.argv[1]).version' "${ts_src}/package.json")"
  [[ -n "${pyver}" ]] || die "pack: no version in sdk/python/pyproject.toml"
  [[ "${pyver}" == "${tsver}" ]] || die "pack: sdk/python is ${pyver} but sdk/typescript is ${tsver}; the two SDKs release in lockstep"
  # The version constants the SDKs report at run time, and the lockfile's
  # root entry, must say the same (they are hand-edited beside the
  # manifests; docs/release-runbook.md "SDK release" lists them).
  # Each is searched for in the package's sources, so moving the constant to
  # another file needs no change here.
  grep -rEq --include='*.py' "^__version__ = \"${pyver}\"\$" "${py_src}/superbased_sdk" \
    || die "pack: no __version__ = \"${pyver}\" under sdk/python/superbased_sdk"
  grep -rEq --include='*.ts' "^export const VERSION = \"${pyver}\";\$" "${ts_src}/src" \
    || die "pack: no export const VERSION = \"${pyver}\"; under sdk/typescript/src"
  [[ "$(node -p 'const l=require(process.argv[1]); l.version + " " + l.packages[""].version' "${ts_src}/package-lock.json")" == "${pyver} ${pyver}" ]] \
    || die "pack: sdk/typescript/package-lock.json does not carry version ${pyver} (run npm install --package-lock-only)"
  # The feedback widget releases with the SDKs, on the same version line
  # (review E-11).
  local wver
  wver="$(node -p 'require(process.argv[1]).version' "${widget_src}/package.json")"
  [[ "${wver}" == "${pyver}" ]] || die "pack: sdk/widget is ${wver} but the SDKs are ${pyver}; the widget releases in lockstep with them"
  [[ "$(node -p 'const l=require(process.argv[1]); l.version + " " + l.packages[""].version' "${widget_src}/package-lock.json")" == "${pyver} ${pyver}" ]] \
    || die "pack: sdk/widget/package-lock.json does not carry version ${pyver} (run npm install --package-lock-only)"
  # The Go SDK (sdk/go) is on the same version line: its Version constant.
  # It ships as a Go module tag (sdk/go/v<x.y.z>), not an artifact here.
  grep -rEq --include='*.go' "^const Version = \"${pyver}\"\$" "${go_src}" \
    || die "pack: no const Version = \"${pyver}\" under sdk/go (the Go SDK releases in lockstep)"
  if [[ -n "${version}" && "${version}" != "${pyver}" ]]; then
    die "pack: --version names ${version} but the manifests say ${pyver}"
  fi
  log "pack: version ${pyver}"

  # Python: sdist and wheel from a clean copy.
  copy_pkg "${py_src}" "${work}/py"
  python3 -m venv "${work}/buildenv"
  "${work}/buildenv/bin/python" -m pip install --quiet --upgrade pip build twine
  "${work}/buildenv/bin/python" -m build --outdir "${out}" "${work}/py"
  "${work}/buildenv/bin/python" -m twine check --strict "${out}"/*.whl "${out}"/*.tar.gz
  local whl sdist
  whl="$(ls "${out}"/superbased_sdk-"${pyver}"-*.whl 2>/dev/null | head -n1)"
  sdist="$(ls "${out}"/superbased_sdk-"${pyver}".tar.gz 2>/dev/null | head -n1)"
  [[ -n "${whl}" ]] || die "pack: no superbased_sdk-${pyver} wheel in ${out}"
  [[ -n "${sdist}" ]] || die "pack: no superbased_sdk-${pyver} sdist in ${out}"
  python3 -c 'import sys,zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "${whl}" >"${work}/whl.txt"
  check_listing "${work}/whl.txt" "the wheel" 'superbased_sdk/__init__\.py' 'superbased_sdk/py\.typed' 'licenses/LICENSE'
  tar -tzf "${sdist}" >"${work}/sdist.txt"
  check_listing "${work}/sdist.txt" "the sdist" 'pyproject\.toml' 'LICENSE' 'superbased_sdk/py\.typed'

  # npm: the tarball npm publish would upload (npm pack runs the prepare
  # script, which builds dist/).
  copy_pkg "${ts_src}" "${work}/ts"
  (cd "${work}/ts" && npm ci --no-progress && npm pack --pack-destination "${out}")
  local tgz="${out}/superbased-sdk-${tsver}.tgz"
  [[ -f "${tgz}" ]] || die "pack: npm pack did not write ${tgz}"
  tar -tzf "${tgz}" >"${work}/tgz.txt"
  check_listing "${work}/tgz.txt" "the npm tarball" 'package/package\.json' 'package/LICENSE' \
    'package/dist/esm/index\.js' 'package/dist/esm/index\.d\.ts' 'package/dist/cjs/index\.js'
  if grep -Eq '(^|/)(src|test)/' "${work}/tgz.txt"; then
    die "pack: the npm tarball carries sources or tests; check package.json files"
  fi

  # npm: the feedback widget's tarball. It ships its TypeScript sources
  # beside dist/ on purpose (package.json files), never its tests.
  copy_pkg "${widget_src}" "${work}/widget"
  (cd "${work}/widget" && npm ci --no-progress && npm pack --pack-destination "${out}")
  local wtgz="${out}/superbased-feedback-widget-${wver}.tgz"
  [[ -f "${wtgz}" ]] || die "pack: npm pack did not write ${wtgz}"
  tar -tzf "${wtgz}" >"${work}/wtgz.txt"
  check_listing "${work}/wtgz.txt" "the widget tarball" 'package/package\.json' 'package/LICENSE' \
    'package/dist/index\.js' 'package/dist/index\.d\.ts' 'package/dist/define\.js' 'package/dist/react\.js'
  if grep -Eq '(^|/)test/' "${work}/wtgz.txt"; then
    die "pack: the widget tarball carries tests; check sdk/widget/package.json files"
  fi
  (cd "${out}" && sha256sum -- *.whl *.tar.gz *.tgz >SHA256SUMS)
  log "pack: wrote $(cd "${out}" && ls | tr '\n' ' ')"
}

case "${1:-}" in
  python) test_python ;;
  node) test_node ;;
  java) test_java ;;
  widget) test_widget ;;
  go) test_go ;;
  pack) shift; pack "$@" ;;
  *) die "usage: sdk.sh python | node | java | widget | go | pack <outdir> [--version <x.y.z>]" ;;
esac
