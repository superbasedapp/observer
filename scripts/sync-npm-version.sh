#!/usr/bin/env bash
# sync-npm-version.sh — stamp a release version into every package.json
# under npm/, including the main package's optionalDependencies refs.
#
# Usage:
#   ./scripts/sync-npm-version.sh v1.2.3
#   ./scripts/sync-npm-version.sh 1.2.3       # leading 'v' optional
#   ./scripts/sync-npm-version.sh --validate-only v1.2.3
#
# --validate-only runs ONLY the strict-SemVer gate below, writes nothing,
# and echoes the normalised (leading-'v'-stripped) version on stdout. It
# exists so a second script can reuse this one's validation instead of
# copy-pasting the regex — scripts/assemble-plugins-repo.sh restamps the
# assembled public tree and must reject exactly the same strings this
# script rejects. One regex, one owner.
#
# Why this script exists: 6 package.json files have to stay version-
# locked in lockstep, and the main package's optionalDependencies
# block has to point at the exact same version of each platform
# package or `npm install` won't pick the right one. Doing this by
# hand on every release is a recipe for one stale ref slipping
# through. The CI release workflow runs this right before `npm
# publish`.

set -euo pipefail

VALIDATE_ONLY=0
if [ "${1:-}" = "--validate-only" ]; then
  VALIDATE_ONLY=1
  shift
fi

if [ "$#" -ne 1 ]; then
  echo "usage: $0 [--validate-only] <version>" >&2
  echo "       version may have a leading 'v' which will be stripped" >&2
  exit 64
fi

# Strip leading 'v' so a git tag like 'v1.2.3' becomes the npm-friendly
# '1.2.3'.
VERSION="${1#v}"

# STRICT SemVer 2.0.0 validation — the official regex from semver.org
# (the "suggested regular expression … for checking a SemVer string",
# https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string),
# pasted verbatim below.
#
# It replaced a permissive `[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?…`
# check that accepted strings SemVer rejects — `01.2.3` (leading zero),
# `1.2.3-01` (numeric pre-release identifier with a leading zero),
# `1.2.3-alpha..1` (empty identifier). That mattered because this script
# stamps a Codex plugin manifest, and Codex's plugin validator requires
# STRICT semver: a mistyped tag would have sailed through the stamp and
# been rejected at plugin-validation time, on the far side of a release.
# Failing loudly here fails it for EVERY channel at once.
#
# Validation runs through node (already a hard requirement of the stamping
# below) so the published regex can be used as written — grep -E has no
# non-capturing groups.
#
# The candidate is passed in the environment, not as an argv tail: with a
# stdin script (`node -`) the argv offset is not worth relying on.
if ! SEMVER_CANDIDATE="$VERSION" node - <<'EOF'
// semver.org's official regex, verbatim.
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
process.exit(SEMVER.test(process.env.SEMVER_CANDIDATE) ? 0 : 1);
EOF
then
  echo "error: '$VERSION' is not a valid SemVer 2.0.0 version" >&2
  echo "       (no leading zeroes in numeric fields, no empty pre-release identifiers;" >&2
  echo "        e.g. 1.2.3, 1.2.3-rc.1, 1.2.3+build.5 are valid — 01.2.3, 1.2.3-01, 1.2.3-alpha..1 are not)" >&2
  exit 65
fi

# Validation-only callers stop here, having mutated nothing. The
# normalised version goes to stdout so the caller can capture it.
if [ "$VALIDATE_ONLY" -eq 1 ]; then
  echo "$VERSION"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NPM_DIR="$REPO_ROOT/npm"

if [ ! -d "$NPM_DIR" ]; then
  echo "error: $NPM_DIR not found — are you running from the repo?" >&2
  exit 66
fi

PACKAGES=(
  observer
  observer-linux-x64
  observer-linux-arm64
  observer-darwin-x64
  observer-darwin-arm64
  observer-win32-x64
)

# Use Node to update the JSON in place — preserves field ordering,
# handles escaping correctly, and is already a dep of any environment
# that publishes to npm. Falls back to nothing — no jq required.
for pkg in "${PACKAGES[@]}"; do
  pkg_path="$NPM_DIR/$pkg/package.json"
  if [ ! -f "$pkg_path" ]; then
    echo "error: missing $pkg_path" >&2
    exit 67
  fi

  node - "$pkg_path" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
pkg.version = version;
// The main package pins each optional dep to an exact version match.
// Any other optionalDependencies ('@superbased/...') get the same
// stamp; foreign deps stay untouched.
if (pkg.optionalDependencies) {
  for (const dep of Object.keys(pkg.optionalDependencies)) {
    if (dep.startsWith('@superbased/observer-')) {
      pkg.optionalDependencies[dep] = version;
    }
  }
}
fs.writeFileSync(filePath, JSON.stringify(pkg, null, 2) + '\n');
EOF

  echo "stamped $pkg → $VERSION"
done

# Also stamp the VS Code extension manifest. The extension's bundled
# observer binary is downloaded from a URL keyed off the extension
# version (plan §15 risk-7 invariant — see
# project_vscode_extension_m0_m6.md), so the two MUST stay in lockstep.
# Without this stamp, vsce package would build with a stale version
# and the Marketplace publish would either re-collide ("already
# exists") or land out-of-band with the npm/PyPI versions. This is
# the bug that surfaced on the v1.8.0 release run.
VSCODE_PKG="$REPO_ROOT/vscode/package.json"
if [ -f "$VSCODE_PKG" ]; then
  node - "$VSCODE_PKG" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
pkg.version = version;
fs.writeFileSync(filePath, JSON.stringify(pkg, null, 2) + '\n');
EOF
  echo "stamped vscode/package.json → $VERSION"
fi

# Also stamp the browser-capture MV3 extension manifest. Like the VS
# Code extension, the browser extension version is stamped in lockstep
# with the observer release tag (proposal §10.4) — this is what binds
# the native-messaging protocol version between the extension and
# `observer browser hook`, so an upgrade never leaves a version-skewed
# bridge.
#
# ONE IMPORTANT DIFFERENCE from npm/vscode semver: a Chrome MV3
# `manifest.json` "version" MUST be one-to-four dot-separated integers
# (each 0–65535) and — unlike semver — does NOT allow a pre-release or
# build-metadata suffix. `1.18.0` is valid; `1.18.0-rc.1` is REJECTED
# by the Web Store at upload. So we stamp the NUMERIC CORE only: strip
# anything from the first '-' (pre-release) or '+' (build metadata).
# A tag like `v1.19.0-rc.1` therefore stamps the manifest to `1.19.0`
# (the npm/vscode packages still carry the full `1.19.0-rc.1`). Note a
# pre-release and its final tag would collide on the manifest version;
# publish the MV3 artifact from the final tag, not an rc.
BROWSER_MANIFEST="$REPO_ROOT/browser-extension/manifest.json"
if [ -f "$BROWSER_MANIFEST" ]; then
  MV3_VERSION="${VERSION%%[-+]*}"
  node - "$BROWSER_MANIFEST" "$MV3_VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const manifest = JSON.parse(fs.readFileSync(filePath, 'utf8'));
manifest.version = version;
fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2) + '\n');
EOF
  echo "stamped browser-extension/manifest.json → $MV3_VERSION"
fi

# Also stamp the in-tool plugin manifests under plugins/ — the Claude
# Code plugin manifest and the single-plugin marketplace catalog entry
# that points at it (docs/plans/adapter-plugins-distribution-plan-2026-07-31.md
# Phase 1). A published plugin's version is the pin Claude Code caches
# on, so an unstamped manifest means installed users never see the new
# release; and the marketplace entry has to agree with the plugin's own
# manifest or `claude plugin validate` warns.
#
# TWO DIFFERENCES from the manifests above:
#
#  1. FULL semver, not the MV3 numeric core. Claude Code treats
#     `version` as an opaque pin string, not a numeric tuple, so a
#     pre-release tag like v1.29.0-rc.1 stamps as `1.29.0-rc.1` — the
#     same string npm and vsce carry. No suffix stripping.
#  2. These two files are GENERATED by `go run ./plugins/plugingen`,
#     which reads this very version out of npm/observer/package.json
#     (already stamped above). We stamp them here with Node instead of
#     re-running the generator because the release job that calls this
#     script has Node but no Go toolchain. The result is byte-identical
#     to a regenerated tree — both write 2-space-indented JSON with a
#     single trailing newline and only replace an existing key's value,
#     so `make verify-plugins-build` still passes on the stamped tree.
#     Regenerate + commit plugins/ (`make plugins-build`) as part of the
#     release stamp, the same as vscode/package.json's pre-flight check.
PLUGIN_MANIFEST="$REPO_ROOT/plugins/claude-code/superbased/.claude-plugin/plugin.json"
if [ -f "$PLUGIN_MANIFEST" ]; then
  node - "$PLUGIN_MANIFEST" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const manifest = JSON.parse(fs.readFileSync(filePath, 'utf8'));
manifest.version = version;
fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2) + '\n');
EOF
  echo "stamped plugins/claude-code/superbased/.claude-plugin/plugin.json → $VERSION"
fi

PLUGIN_MARKETPLACE="$REPO_ROOT/plugins/claude-code/.claude-plugin/marketplace.json"
if [ -f "$PLUGIN_MARKETPLACE" ]; then
  node - "$PLUGIN_MARKETPLACE" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const manifest = JSON.parse(fs.readFileSync(filePath, 'utf8'));
// Stamp every catalog entry that already carries a version. An entry
// WITHOUT one is deliberately pinned to its git SHA (Claude Code's
// commit-SHA versioning mode), so don't invent a version for it.
for (const entry of manifest.plugins || []) {
  if (entry.version) {
    entry.version = version;
  }
}
fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2) + '\n');
EOF
  echo "stamped plugins/claude-code/.claude-plugin/marketplace.json → $VERSION"
fi

# Phase 2/3 plugin surfaces. Same rules as the two above: FULL semver (a
# Gemini extension version is only compared to detect a newer release, and
# Codex's plugin spec requires strict semver — which a `-rc.1` pre-release
# satisfies), and both files are GENERATED by `go run ./plugins/plugingen`
# from this very number, so a Node stamp lands byte-identical to a
# regenerated tree.
#
# The Codex MARKETPLACE catalog is deliberately absent from this list: the
# documented entry schema for a `local` source has no version field (the
# plugin's own manifest is the pin), so there is nothing to stamp there.
# The Droid and Qoder catalogs are absent for the same reason (verified for
# Qoder against the CLI: with no entry version it reports the plugin
# manifest's).
# plugins/goose/ is version-free too — a Goose extension is just a command.
#
# THIS LIST IS PINNED. plugins/plugingen's
# TestSyncNpmVersionStampsEveryVersionBearingManifest reads this script,
# extracts the plugins/… paths named below, and requires set equality with
# the version-bearing manifests the generator actually emits — in BOTH
# directions. A new version-bearing manifest that is not added here fails
# `go test ./plugins/...`, which is how the five coverage-wave manifests
# stopped being invisible to the release stamp.
#
# The coverage waves (plan §7) added six more version-bearing manifests,
# each generated from this same number:
#
#   wave A — kimi.plugin.json, Qoder's .qoder-plugin/plugin.json, Devin's
#            .devin-plugin/plugin.json, Droid's .factory-plugin/plugin.json
#            and openclaw.plugin.json.
#   wave C — the Claude Desktop MCP bundle manifest
#            (plugins/cowork/superbased/manifest.json, whose `version` is
#            required to be semver by the .mcpb spec).
#
# NOT in the list, and each for a documented reason:
#   * plugins/antigravity/ — its plugin.json documents exactly ONE field
#     (`name`). There is no version key to stamp.
#   * plugins/droid/.factory-plugin/marketplace.json — Factory's catalog
#     entry schema carries no version (the plugin's manifest is the pin),
#     like Codex's.
#   * every wave-B listing and the wave-C pi / command-code / copilot
#     surfaces — they are READMEs and a URI, with no version field at all.
for gen_manifest in \
  "plugins/gemini/gemini-extension.json" \
  "plugins/codex/plugins/superbased/.codex-plugin/plugin.json" \
  "plugins/kimi-code/superbased/kimi.plugin.json" \
  "plugins/qoder/superbased/.qoder-plugin/plugin.json" \
  "plugins/devin/superbased/.devin-plugin/plugin.json" \
  "plugins/droid/factory/superbased/.factory-plugin/plugin.json" \
  "plugins/openclaw/superbased/openclaw.plugin.json" \
  "plugins/cowork/superbased/manifest.json"
do
  gen_path="$REPO_ROOT/$gen_manifest"
  [ -f "$gen_path" ] || continue
  node - "$gen_path" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const manifest = JSON.parse(fs.readFileSync(filePath, 'utf8'));
manifest.version = version;
fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2) + '\n');
EOF
  echo "stamped $gen_manifest → $VERSION"
done

# The OpenCode npm plugin. Unlike the manifests above this one is
# HAND-WRITTEN (plugingen owns only its wiring constants + README), but it
# is still version-locked to the observer release: the plugin declares an
# MCP server that launches this release's binary, and the package is
# published from the same tag.
OPENCODE_PKG="$REPO_ROOT/plugins/opencode/package.json"
if [ -f "$OPENCODE_PKG" ]; then
  node - "$OPENCODE_PKG" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
pkg.version = version;
fs.writeFileSync(filePath, JSON.stringify(pkg, null, 2) + '\n');
EOF
  echo "stamped plugins/opencode/package.json → $VERSION"
fi

# Enterprise version lockstep (enterprise deployment Phase 0, contract C6).
# The harness-gateway image and the observer-org Helm chart ship beside the
# observer-org image under the SAME release tag, and the org binary embeds
# the chart (`observer-org deploy export`), so neither number may drift
# from the release. Both carry FULL semver like npm / vsce (a pre-release
# stamps as 1.2.3-rc.1). Each stamp is READ BACK and compared, because a
# silent no-op here ships a chart or an image label that still says the
# previous release — the failure the lockstep exists to make impossible.
HARNESS_PKG="$REPO_ROOT/harness-gateway/package.json"
if [ -f "$HARNESS_PKG" ]; then
  node - "$HARNESS_PKG" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
pkg.version = version;
fs.writeFileSync(filePath, JSON.stringify(pkg, null, 2) + '\n');
const back = JSON.parse(fs.readFileSync(filePath, 'utf8')).version;
if (back !== version) {
  console.error(`error: ${filePath} reads back version ${back}, want ${version}`);
  process.exit(68);
}
EOF
  echo "stamped harness-gateway/package.json → $VERSION"
fi

# The lock file carries the package's own version twice (the root
# `version` and `packages[""].version`), and `npm ci` — which the
# harness_image job and the Dockerfile both run — refuses a lock whose
# root entry disagrees with package.json. Stamp both, read both back.
HARNESS_LOCK="$REPO_ROOT/harness-gateway/package-lock.json"
if [ -f "$HARNESS_LOCK" ]; then
  node - "$HARNESS_LOCK" "$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, version] = process.argv;
const lock = JSON.parse(fs.readFileSync(filePath, 'utf8'));
lock.version = version;
if (lock.packages && lock.packages['']) {
  lock.packages[''].version = version;
}
fs.writeFileSync(filePath, JSON.stringify(lock, null, 2) + '\n');
const back = JSON.parse(fs.readFileSync(filePath, 'utf8'));
const rootBack = back.version;
const pkgBack = back.packages && back.packages[''] ? back.packages[''].version : version;
if (rootBack !== version || pkgBack !== version) {
  console.error(`error: ${filePath} reads back version ${rootBack} / packages[""].version ${pkgBack}, want ${version}`);
  process.exit(68);
}
EOF
  echo "stamped harness-gateway/package-lock.json → $VERSION"
fi

# Chart.yaml's appVersion is the image tag the chart pins by default, so it
# carries the tag form ("v1.2.3", quoted — a bare 1.2.3 would be a YAML
# float for some inputs). Only the appVersion line changes; the chart's own
# `version:` is a chart-schema number bumped by hand on chart changes.
CHART_YAML="$REPO_ROOT/charts/observer-org/Chart.yaml"
if [ -f "$CHART_YAML" ]; then
  node - "$CHART_YAML" "v$VERSION" <<'EOF'
const fs = require('fs');
const [, , filePath, appVersion] = process.argv;
const before = fs.readFileSync(filePath, 'utf8');
const re = /^appVersion: .*$/m;
if (!re.test(before)) {
  console.error(`error: ${filePath} has no appVersion line to stamp`);
  process.exit(68);
}
fs.writeFileSync(filePath, before.replace(re, `appVersion: "${appVersion}"`));
const back = fs.readFileSync(filePath, 'utf8').match(re)[0];
if (back !== `appVersion: "${appVersion}"`) {
  console.error(`error: ${filePath} reads back ${back}, want appVersion: "${appVersion}"`);
  process.exit(68);
}
EOF
  echo "stamped charts/observer-org/Chart.yaml appVersion → v$VERSION"
fi

echo "done — $VERSION written to $(echo "${PACKAGES[*]}" | wc -w) package.json files + vscode/package.json + browser-extension/manifest.json + 11 plugins/ manifests + harness-gateway/package.json + package-lock.json + charts/observer-org/Chart.yaml appVersion"
