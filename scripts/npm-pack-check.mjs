#!/usr/bin/env node
// npm-pack-check.mjs: check the seven npm tarballs the release packs before
// any of them reaches a GitHub release (and, from there, npm).
//
// The release workflow's pack step runs `npm pack <dir> --json` for each
// package under npm/ and writes the JSON to $RUNNER_TEMP/pack-<dir>.json,
// with the tarballs in ./npm-tarballs. This script then checks, per package:
//
//   - the packed name and version are the expected ones (the short name
//     `superbased` rides at major + 2, scripts/sync-npm-version.sh);
//   - every `bin` target its package.json declares is in the tarball, and
//     each platform package carries its observer binary;
//   - the tarball was written, and npm-tarballs/ holds exactly seven.
//
// superbased 3.42.1 was published without bin/superbased.js (the file was
// gitignored, so a clean checkout packed three files), which made
// `npx superbased` fail. This is the check that refuses that shape.
//
// Inputs (environment): VERSION (the observer version, no leading v),
// SHORT_VERSION (the superbased version), RUNNER_TEMP (where the pack JSON
// is), and optionally NPM_DIR (default npm) and TARBALL_DIR (default
// npm-tarballs). Exit 0 when every check passes, 1 otherwise, with one
// `::error::` line per problem.

import fs from 'node:fs';
import path from 'node:path';

// PACKAGE_DIRS is every directory under npm/ that is published, in
// dependency order (the order the public publish.yml publishes in).
const PACKAGE_DIRS = [
  'observer-linux-x64',
  'observer-linux-arm64',
  'observer-darwin-x64',
  'observer-darwin-arm64',
  'observer-win32-x64',
  'observer',
  'superbased',
];

function main() {
  const version = process.env.VERSION;
  const shortVersion = process.env.SHORT_VERSION;
  const packDir = process.env.RUNNER_TEMP;
  const npmDir = process.env.NPM_DIR || 'npm';
  const tarballDir = process.env.TARBALL_DIR || 'npm-tarballs';
  if (!version || !shortVersion || !packDir) {
    console.log('::error::npm-pack-check: VERSION, SHORT_VERSION and RUNNER_TEMP must be set');
    return 1;
  }
  const bad = [];
  for (const dir of PACKAGE_DIRS) {
    let pack;
    let manifest;
    try {
      [pack] = JSON.parse(fs.readFileSync(path.join(packDir, `pack-${dir}.json`), 'utf8'));
      manifest = JSON.parse(fs.readFileSync(path.join(npmDir, dir, 'package.json'), 'utf8'));
    } catch (err) {
      bad.push(`${dir}: ${err.message}`);
      continue;
    }
    const wantName = dir === 'superbased' ? 'superbased' : `@superbased/${dir}`;
    const wantVersion = dir === 'superbased' ? shortVersion : version;
    if (pack.name !== wantName) bad.push(`${dir}: packed ${pack.name}, want ${wantName}`);
    if (pack.version !== wantVersion) bad.push(`${dir}: packed version ${pack.version}, want ${wantVersion}`);
    const files = new Set((pack.files || []).map((f) => f.path));
    const need = new Set(Object.values(manifest.bin || {}).map((p) => p.replace(/^\.\//, '')));
    if (dir.startsWith('observer-')) {
      need.add(dir === 'observer-win32-x64' ? 'bin/observer.exe' : 'bin/observer');
    }
    for (const f of need) {
      if (!files.has(f)) bad.push(`${dir}: ${pack.filename} lacks ${f}`);
    }
    if (!pack.filename || !fs.existsSync(path.join(tarballDir, pack.filename))) {
      bad.push(`${dir}: ${pack.filename} was not written to ${tarballDir}`);
    }
    console.log(`${pack.filename}  ${pack.entryCount} files  ${pack.integrity}`);
  }
  let tgz = [];
  try {
    tgz = fs.readdirSync(tarballDir).filter((n) => n.endsWith('.tgz'));
  } catch (err) {
    bad.push(err.message);
  }
  if (tgz.length !== PACKAGE_DIRS.length) {
    bad.push(`${tarballDir}/ holds ${tgz.length} tarballs, want ${PACKAGE_DIRS.length}`);
  }
  for (const b of bad) console.log(`::error::${b}`);
  return bad.length === 0 ? 0 : 1;
}

process.exitCode = main();
