#!/usr/bin/env node
// @superbased/observer postinstall: PRINT-ONLY (T-753).
//
// On every OS it prints one next-step line (Getting started v2): run
// `observer start`, which opens the dashboard, where signing in is the
// recommended next step. It never starts anything itself.
//
// `npm install -g` over an older version swaps the platform package's
// directory underneath a running Observer daemon: the old process keeps
// running the deleted binary until it is restarted (the rc.3 roll found
// every npm node in that state). npm must never restart it: the daemon IS the
// proxy on :8820, and stopping it while an AI session routes through it
// breaks that session (`observer service restart` is the safe restart). So this script only
// looks (Linux: /proc/<pid>/exe of `observer start` processes running a
// replaced @superbased package binary, see below) and prints what to run. It
// never downloads, writes, signals or fails the install.
//
// npm 10 does NOT delete the old package directory before this script runs
// (T-756, seen on the rc.4 roll): reify renames it aside to a retired dot-dir
// (@superbased/.observer-linux-x64-<random>/), runs postinstall, and only
// then removes it. At this point the daemon's exe therefore reads the
// retired path WITHOUT "(deleted)". So a daemon is stale when its executable
// is an @superbased observer binary and any of these holds: the file was
// deleted, it lives under a retired dot-dir, or it is not the binary this
// install just put in place.
//
// npm 7 and later hide lifecycle-script output unless --foreground-scripts,
// so the note goes to the controlling terminal when there is one, else to
// stderr. OBSERVER_POSTINSTALL_PROC_ROOT points it at a fixture /proc and
// OBSERVER_POSTINSTALL_INSTALLED_BINARY names the installed binary
// (scripts/test-npm-postinstall.sh); they only change where it reads.
'use strict';

const fs = require('fs');
const path = require('path');

const DELETED = ' (deleted)';

// installedBinary is the real path of the platform binary this install put in
// place, or '' when it cannot be resolved (then only the deleted and
// retired-dir shapes count).
function installedBinary() {
  const override = process.env.OBSERVER_POSTINSTALL_INSTALLED_BINARY;
  if (override) return override;
  try {
    const pkg = '@superbased/observer-' + process.platform + '-' + process.arch;
    return fs.realpathSync(require.resolve(pkg + '/bin/observer'));
  } catch (_) {
    return '';
  }
}

// retiredDir reports whether bin sits under a directory npm renamed aside:
// a path segment after @superbased/ that starts with a dot.
function retiredDir(bin) {
  const i = bin.indexOf('/@superbased/');
  if (i < 0) return false;
  return bin
    .slice(i + '/@superbased/'.length)
    .split('/')
    .some((seg) => seg.startsWith('.'));
}

// staleDaemons lists `observer start` processes whose executable is an
// @superbased package binary that this install replaced: deleted, under a
// retired dot-dir, or simply not the installed binary.
function staleDaemons(procRoot, installed) {
  const out = [];
  let entries = [];
  try {
    entries = fs.readdirSync(procRoot);
  } catch (_) {
    return out;
  }
  for (const pid of entries) {
    if (!/^[0-9]+$/.test(pid)) continue;
    let exe;
    let cmdline;
    try {
      exe = fs.readlinkSync(path.join(procRoot, pid, 'exe'));
      cmdline = fs.readFileSync(path.join(procRoot, pid, 'cmdline'), 'latin1').split('\0');
    } catch (_) {
      continue;
    }
    const deleted = exe.endsWith(DELETED);
    const bin = deleted ? exe.slice(0, -DELETED.length) : exe;
    if (!bin.includes('/@superbased/') || !path.basename(bin).startsWith('observer')) continue;
    if (!cmdline.slice(1).includes('start')) continue;
    if (!deleted && !retiredDir(bin) && !(installed && bin !== installed)) continue;
    out.push(pid);
  }
  return out.sort((a, b) => Number(a) - Number(b));
}

// underServiceUnit reports whether pid runs inside the observer systemd unit
// (its cgroup path names observer.service). U7: the hint names only the
// restart path that applies to the daemon(s) found.
function underServiceUnit(procRoot, pid) {
  try {
    const cg = fs.readFileSync(path.join(procRoot, pid, 'cgroup'), 'latin1');
    return /\/observer\.service(\/|$|\n)/m.test(cg);
  } catch (_) {
    return false;
  }
}

function note(pids, procRoot) {
  const which = pids.length === 1 ? 'pid ' + pids[0] : 'pids ' + pids.join(', ');
  const root = procRoot || '/proc';
  const unit = pids.some((p) => underServiceUnit(root, p));
  const plain = pids.some((p) => !underServiceUnit(root, p));
  const lines = ['', '@superbased/observer: updated, but the running Observer daemon (' + which + ') still runs the previous binary.'];
  if (unit) {
    lines.push(
      '  It runs as the systemd service: run (as yourself, not with sudo)  observer service upgrade',
      '    It restarts the daemon only when no proxy route or proxied session is live, and otherwise prints the safe order.'
    );
  }
  if (plain) {
    lines.push(
      '  It was started with `observer start`: restart it with  observer service restart',
      '    It takes the proxy routes off first, has the daemon restart itself in place, and puts them back.'
    );
  }
  lines.push('  npm restarts nothing.', '');
  return lines.join('\n');
}

function emit(text) {
  try {
    const fd = fs.openSync('/dev/tty', 'w');
    try {
      fs.writeSync(fd, text);
    } finally {
      fs.closeSync(fd);
    }
    return;
  } catch (_) {
    // no controlling terminal
  }
  process.stderr.write(text);
}

// NEXT_STEP is the one line every fresh install prints, on every OS.
const NEXT_STEP = 'Installed. Next: observer start (opens your dashboard, where you sign in)\n';

// main prints the stale-daemon note when an updated install left a running
// daemon on the previous binary (Linux only: it reads /proc), and otherwise
// the next-step line.
function main() {
  if (process.platform === 'linux') {
    const root = process.env.OBSERVER_POSTINSTALL_PROC_ROOT || '/proc';
    const pids = staleDaemons(root, installedBinary());
    if (pids.length > 0) {
      emit(note(pids, root));
      return;
    }
  }
  emit(NEXT_STEP);
}

if (require.main === module) {
  try {
    main();
  } catch (_) {
    // print-only: never fail an install
  }
  process.exit(0);
}

module.exports = { staleDaemons, note, retiredDir, installedBinary, underServiceUnit, NEXT_STEP };
