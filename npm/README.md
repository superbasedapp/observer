# npm packages for SuperBased Observer

This directory contains the npm distribution wrappers for the
`observer` Go binary. The runtime code stays in Go (`./cmd/observer`,
`./internal/...`); these packages exist only to ship pre-built
binaries via npm so JavaScript/TypeScript ecosystems can install the
tool with `npm install -g @superbased/observer`.

## Package layout

| Directory                 | Purpose                                                            |
| ------------------------- | ------------------------------------------------------------------ |
| `observer/`               | Main package — Node shim + `optionalDependencies` per platform.    |
| `observer-linux-x64/`     | Linux x64 binary.                                                  |
| `observer-linux-arm64/`   | Linux arm64 binary.                                                |
| `observer-darwin-x64/`    | macOS Intel binary.                                                |
| `observer-darwin-arm64/`  | macOS Apple Silicon binary.                                        |
| `observer-win32-x64/`     | Windows x64 binary.                                                |
| `superbased/`             | The short name `superbased`; depends on the exact main package.    |

Each per-platform package's `package.json` carries `os` + `cpu`
fields so npm only installs the matching one. The main package's
`bin/observer.js` shim resolves `@superbased/observer-<platform>-<arch>`
at runtime via `require.resolve()` and spawns the binary inside.

## Versioning

The six `@superbased/observer*` packages share the same version, and
`superbased` carries it with the major raised by 2 (observer 1.43.0 is
superbased 3.43.0). The `scripts/sync-npm-version.sh` script stamps the
real version (from the git tag) into all seven right before packing.

## Publishing (CI, the normal flow)

The packages are published with npm trusted publishing (OIDC): no npm
token is involved, and every version carries npm provenance. On a `v*`
release tag the maintainers' release run:

1. Cross-compiles 5 binaries via `GOOS=… GOARCH=… go build`.
2. Drops each binary into the matching `npm/observer-<plat>-<arch>/bin/`
   directory.
3. Runs `scripts/sync-npm-version.sh ${TAG}` to stamp the version (the
   short name in `superbased/` gets the major raised by 2).
4. Runs `npm pack` for the seven packages and checks them with
   `scripts/npm-pack-check.mjs`.
5. Attaches the seven tarballs, listed in the vendor-signed `SHA256SUMS`,
   to this repository's GitHub release, and publishes the release.

Publishing the release runs `.github/workflows/publish.yml` here. Its
`npm` job, in the GitHub environment `npm`, verifies the tarballs against
`SHA256SUMS` and its signature (`scripts/publish-verify.sh`), then runs
`npm publish <tarball> --access public --provenance` for the platform
packages, the main package and `superbased`, in that order
(`scripts/publish-npm.sh`); from a final release it then publishes the
SDK packages `@superbased/sdk` and `@superbased/feedback-widget`. Each
package has a trusted publisher on npmjs.com for this repository, that
workflow file and the environment `npm`. The same workflow's `pypi` job
uploads the PyPI wheels.

## Publishing manually (rarely needed — only for emergencies)

```bash
# 0. From a clean git working tree at the tag you want to release.
TAG=v1.2.3
./scripts/sync-npm-version.sh "$TAG"

# 1. Cross-compile each platform. Go does this without CGO since
#    we use modernc.org/sqlite.
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o npm/observer-linux-x64/bin/observer    ./cmd/observer
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o npm/observer-linux-arm64/bin/observer  ./cmd/observer
GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o npm/observer-darwin-x64/bin/observer   ./cmd/observer
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o npm/observer-darwin-arm64/bin/observer ./cmd/observer
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o npm/observer-win32-x64/bin/observer.exe ./cmd/observer

# 2. Make the unix binaries executable (Windows .exe doesn't need this).
chmod +x npm/observer-{linux-x64,linux-arm64,darwin-x64,darwin-arm64}/bin/observer

# 3. Publish each platform package, then the main package last.
for p in observer-linux-x64 observer-linux-arm64 observer-darwin-x64 \
         observer-darwin-arm64 observer-win32-x64 observer; do
  (cd "npm/$p" && npm publish --access public)
done
```

## Local smoke test (before publishing)

```bash
# Build just your host's binary into the matching slot:
make build-npm-local

# Then tarball + install in a temp dir:
cd npm/observer && npm pack
mkdir -p /tmp/observer-npm-test && cd /tmp/observer-npm-test
npm init -y && npm install /home/marmutapp/superbased-observer/npm/observer/superbased-observer-*.tgz
./node_modules/.bin/observer --version
```

## Why this shape

`optionalDependencies` per platform is the modern best practice for
npm-distributing a native binary. Same shape used by `esbuild`,
`@swc/cli`, `@biomejs/biome`, `prisma`, `bun`. Tradeoffs vs alternatives:

- **vs postinstall download script**: faster install, works offline
  once cached, nothing downloaded at install time (some orgs disable
  install scripts). The one postinstall step (`bin/postinstall.js`, T-753)
  only PRINTS a restart hint when a running Observer daemon still runs the
  binary the upgrade replaced; with scripts disabled the install is the
  same, minus that note.
- **vs single platform-detect-at-runtime package**: the package
  installed is small (one binary, ~25 MB) instead of containing all 5
  (~125 MB).
- **vs WASM**: not feasible — observer needs filesystem watching,
  HTTP server bindings, and SQLite, none of which are well-supported
  in Node WASM.
