// Unit tests for the Windows warm-up of a newly adopted binary (lane
// shr-hookseam2, milestone 3): one background `--version` run per adopted
// path and version, on Windows only, never blocking activation.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  WARMUP_ARGS,
  WARMUP_STATE_KEY,
  planWarmup,
  warmUpAdoptedBinary,
  warmUpOnAdoption,
  warmupKey,
  type WarmupDeps,
} from '../../src/warmup';

const BIN = { path: 'C:\\ext\\bin\\observer.exe', version: '1.40.0' };

function deps(over: Partial<WarmupDeps> = {}): WarmupDeps & { runs: string[]; remembered: string[] } {
  const runs: string[] = [];
  const remembered: string[] = [];
  return {
    platform: 'win32',
    lastKey: undefined,
    remember: (k) => {
      remembered.push(k);
    },
    run: async (bin, args) => {
      runs.push(`${bin} ${args.join(' ')}`);
    },
    runs,
    remembered,
    ...over,
  };
}

describe('planWarmup', () => {
  const key = warmupKey(BIN);
  const rows: Array<[string, string, string | undefined, boolean]> = [
    ['new binary on Windows', 'win32', undefined, true],
    ['a different binary was warmed before', 'win32', 'C:\\old\\observer.exe|1.39.0', true],
    ['already warmed', 'win32', key, false],
    ['Linux', 'linux', undefined, false],
    ['macOS', 'darwin', undefined, false],
  ];
  for (const [name, platform, last, want] of rows) {
    test(name, () => {
      const plan = planWarmup(platform, key, last);
      assert.equal(plan.run, want);
      assert.ok(plan.why.length > 0);
    });
  }
  test('no adopted binary', () => {
    assert.equal(planWarmup('win32', warmupKey({ path: '', version: '' }), undefined).run, false);
  });
});

describe('warmUpAdoptedBinary', () => {
  test('runs the adopted binary once with --version and remembers it', async () => {
    const d = deps();
    assert.equal(await warmUpAdoptedBinary(BIN, d), true);
    assert.deepEqual(d.runs, [`${BIN.path} ${WARMUP_ARGS.join(' ')}`]);
    assert.deepEqual(d.remembered, [warmupKey(BIN)]);
  });

  test('is a no-op off Windows', async () => {
    const d = deps({ platform: 'linux' });
    assert.equal(await warmUpAdoptedBinary(BIN, d), false);
    assert.deepEqual(d.runs, []);
    assert.deepEqual(d.remembered, []);
  });

  test('runs once per adopted binary, not on every activation', async () => {
    const d = deps({ lastKey: warmupKey(BIN) });
    assert.equal(await warmUpAdoptedBinary(BIN, d), false);
    assert.deepEqual(d.runs, []);
  });

  test('never rejects when the run or the state write fails', async () => {
    const d = deps({
      run: async () => {
        throw new Error('spawn failed');
      },
      remember: () => {
        throw new Error('state unavailable');
      },
    });
    assert.equal(await warmUpAdoptedBinary(BIN, d), true);
  });

  test('never blocks the caller: it returns before the run finishes', async () => {
    let finish: () => void = () => {};
    const d = deps({ run: () => new Promise<void>((r) => (finish = r)) });
    let settled = false;
    const p = warmUpAdoptedBinary(BIN, d).then(() => (settled = true));
    await Promise.resolve();
    assert.equal(settled, false, 'the warm-up is still running in the background');
    finish();
    await p;
    assert.equal(settled, true);
  });
});

describe('warmUpOnAdoption', () => {
  test('reads and writes the remembered key in globalState', async () => {
    const store = new Map<string, unknown>([[WARMUP_STATE_KEY, warmupKey(BIN)]]);
    const ctx = {
      globalState: {
        get: <T>(k: string) => store.get(k) as T | undefined,
        update: async (k: string, v: unknown) => {
          store.set(k, v);
        },
      },
    };
    // Already warmed on this machine (or not Windows): nothing runs.
    assert.equal(await warmUpOnAdoption(ctx, BIN), false);
  });
});
