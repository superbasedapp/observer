// Unit tests for the O7 guard: when a `binary`-method daemon has self-updated,
// the extension must report and launch the NEWER installed binary rather than
// relaunching its own older bundled copy
// (docs/plans/enterprise-update-management-plan-2026-09-07.md §6 O7,
// acceptance 15).
//
// Without the guard, an extension pinned to release N relaunches its bundled
// copy over a node that just updated itself to N+1, and the two thrash: the
// daemon updates, the extension puts the old one back on the next activation.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  isStrictlyNewer,
  resolveLocalBinary,
  type LocalBinaryProbes,
  type VersionProbe,
} from '../../src/binary-internals';

// probes builds a resolver harness whose PATH and bundled binaries report the
// versions the test names. `pathBinary` undefined means nothing on PATH.
function probes(opts: {
  bundledVersion: string;
  pathVersion?: string;
  preferPathBinary?: boolean;
  settingPath?: string;
}): LocalBinaryProbes & { probed: string[] } {
  const probed: string[] = [];
  const versions: Record<string, string> = { '/ext/bin/observer': opts.bundledVersion };
  if (opts.pathVersion !== undefined) {
    versions['/usr/local/bin/observer'] = opts.pathVersion;
  }
  return {
    settingPath: opts.settingPath,
    bundledPath: '/ext/bin/observer',
    preferPathBinary: opts.preferPathBinary ?? false,
    fileExists: async (p: string) => p in versions,
    which: async () =>
      opts.pathVersion === undefined ? undefined : '/usr/local/bin/observer',
    probeVersion: async (p: string): Promise<VersionProbe> => {
      probed.push(p);
      const v = versions[p];
      return v ? { ok: true, version: v } : { ok: false, version: 'unknown' };
    },
    probed,
  };
}

describe('isStrictlyNewer', () => {
  test('orders release cores', () => {
    assert.equal(isStrictlyNewer('1.33.0', '1.32.0'), true);
    assert.equal(isStrictlyNewer('1.32.1', '1.32.0'), true);
    assert.equal(isStrictlyNewer('2.0.0', '1.99.99'), true);
    assert.equal(isStrictlyNewer('1.9.0', '1.10.0'), false, '1.9 is older than 1.10, not newer');
    assert.equal(isStrictlyNewer('1.32.0', '1.32.0'), false, 'equal is not strictly newer');
  });

  test('strips a leading v and a pre-release suffix', () => {
    assert.equal(isStrictlyNewer('v1.33.0', '1.32.0'), true);
    assert.equal(isStrictlyNewer('1.33.0-rc.1', 'v1.32.0'), true);
    assert.equal(isStrictlyNewer('1.33.0+build.7', '1.33.0'), false);
  });

  test('ANY uncertainty answers false', () => {
    // probeVersion returns the literal 'unknown' when --version printed
    // something it could not parse. That is an absence of information, and the
    // safe reading is "do not switch away from the copy we shipped".
    assert.equal(isStrictlyNewer('unknown', '1.32.0'), false);
    assert.equal(isStrictlyNewer('1.33.0', 'unknown'), false);
    assert.equal(isStrictlyNewer('', '1.32.0'), false);
    assert.equal(isStrictlyNewer('dev', '1.32.0'), false);
    assert.equal(isStrictlyNewer('1.33', '1.32.0'), false);
  });
});

describe('resolveLocalBinary O7 guard', () => {
  test('a NEWER installed binary wins over the bundled copy', async () => {
    const p = probes({ bundledVersion: '1.32.0', pathVersion: '1.33.0' });
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'path');
    assert.equal(res.hit?.version, '1.33.0');
    assert.equal(res.hit?.path, '/usr/local/bin/observer');
  });

  test('an OLDER installed binary does not displace the bundled copy', async () => {
    const p = probes({ bundledVersion: '1.33.0', pathVersion: '1.30.0' });
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'bundled');
    assert.equal(res.hit?.version, '1.33.0');
  });

  test('an EQUAL installed binary leaves the bundled copy in place', async () => {
    // The bundled-first ordering exists because the bundled copy is always
    // present and correct; an equal version is no reason to give that up.
    const p = probes({ bundledVersion: '1.33.0', pathVersion: '1.33.0' });
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'bundled');
  });

  test('an unorderable installed version never displaces the bundled copy', async () => {
    const p = probes({ bundledVersion: '1.33.0', pathVersion: 'unknown' });
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'bundled');
  });

  test('no binary on PATH leaves the bundled copy selected', async () => {
    const p = probes({ bundledVersion: '1.33.0' });
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'bundled');
  });

  test('the guard re-probes on every call rather than trusting a cache', async () => {
    // O7 requires a re-probe on activation. The resolver holds no state, so
    // the proof is that two calls each run the version probes again - a cached
    // answer would leave the second call with no new probe records.
    const p = probes({ bundledVersion: '1.32.0', pathVersion: '1.33.0' });
    await resolveLocalBinary(p);
    const first = p.probed.length;
    await resolveLocalBinary(p);
    assert.ok(p.probed.length > first, 'the second resolution must re-probe, not reuse a cached version');
  });

  test('an explicit observer.binary.path still wins over both', async () => {
    // The setting is the operator saying "use this one"; the guard must not
    // override an explicit choice with a newer PATH binary.
    const p = probes({ bundledVersion: '1.32.0', pathVersion: '1.99.0' });
    p.settingPath = '/ext/bin/observer';
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'setting');
  });

  test('preferPathBinary is unaffected: PATH is already first', async () => {
    const p = probes({ bundledVersion: '1.33.0', pathVersion: '1.30.0', preferPathBinary: true });
    const res = await resolveLocalBinary(p);
    assert.equal(res.hit?.source, 'path', 'the opt-in ordering is the operator’s explicit choice and is left alone');
  });
});
