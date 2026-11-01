#!/usr/bin/env node
// @superbased/observer — Node shim that locates the platform-specific
// binary shipped via an optional dependency and spawns it with
// arguments, stdio, and exit code forwarded.
//
// Why this shape: each per-platform binary is published as its own
// optional npm package (`@superbased/observer-<platform>-<arch>`) tagged
// with `os` and `cpu` in its package.json. npm only installs the one
// that matches the user's machine, so installs are fast and small.
// Same pattern used by esbuild, swc, biome.
'use strict';

const { spawn } = require('child_process');
const path = require('path');

const PLATFORM_PACKAGES = {
  'linux-x64': '@superbased/observer-linux-x64',
  'linux-arm64': '@superbased/observer-linux-arm64',
  'darwin-x64': '@superbased/observer-darwin-x64',
  'darwin-arm64': '@superbased/observer-darwin-arm64',
  'win32-x64': '@superbased/observer-win32-x64',
};

function reportUnsupported(key) {
  process.stderr.write(
    '@superbased/observer: no prebuilt binary for ' + key + '.\n' +
    'Supported: ' + Object.keys(PLATFORM_PACKAGES).join(', ') + '.\n' +
    'If you need a different platform, file an issue at\n' +
    '  https://github.com/superbasedapp/observer/issues\n'
  );
  process.exit(1);
}

function reportMissingPackage(pkg) {
  // On Windows name npm.cmd: PowerShell's default execution policy refuses
  // the npm.ps1 shim a bare `npm` resolves to, and npm.cmd also runs in
  // Command Prompt.
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  process.stderr.write(
    '@superbased/observer: optional dependency ' + pkg + ' is not installed.\n' +
    'This usually means npm skipped optional dependencies during install.\n' +
    'Retry with:\n' +
    '  ' + npm + ' install --include=optional @superbased/observer\n' +
    'or, if installed globally:\n' +
    '  ' + npm + ' install -g --include=optional @superbased/observer\n'
  );
  process.exit(1);
}

function resolveBinary() {
  const key = process.platform + '-' + process.arch;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) reportUnsupported(key);

  // Node's resolver looks in node_modules of the calling package +
  // ancestors. Both the global-install and local-install layouts work
  // because the optional dep lives next to (or one level up from) this
  // shim's containing package.
  const exe = process.platform === 'win32' ? 'observer.exe' : 'observer';
  let resolved;
  try {
    resolved = require.resolve(pkg + '/bin/' + exe);
  } catch (err) {
    reportMissingPackage(pkg);
  }
  return resolved;
}

function main() {
  const binary = resolveBinary();
  const child = spawn(binary, process.argv.slice(2), {
    stdio: 'inherit',
    windowsHide: true,
  });
  child.on('error', (err) => {
    process.stderr.write('@superbased/observer: failed to spawn ' + binary + '\n' + err.message + '\n');
    process.exit(127);
  });
  // Forward signals so Ctrl-C / SIGTERM reach the underlying observer
  // (long-running daemons rely on graceful shutdown).
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => {
      if (!child.killed) child.kill(sig);
    });
  }
  child.on('exit', (code, signal) => {
    if (signal) {
      // Re-raise the same signal on this process so the parent shell
      // sees the standard exit-by-signal status.
      process.kill(process.pid, signal);
    } else {
      process.exit(code === null ? 0 : code);
    }
  });
}

main();
