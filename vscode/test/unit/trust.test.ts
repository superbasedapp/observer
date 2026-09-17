// Unit tests for the workspace-trust gate (P1-5: a cloned repo's
// .vscode/settings.json must not be able to choose the daemon binary this
// extension spawns). See src/trust-internals.ts and the gate at the top of
// activate() in src/extension.ts.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  RESTRICTED_TRUST_SETTINGS,
  shouldDeferActivation,
  untrustedWorkspaceWarning,
} from '../../src/trust-internals';

describe('shouldDeferActivation', () => {
  test('defers when the workspace is not trusted', () => {
    assert.equal(shouldDeferActivation(false), true);
  });

  test('does not defer when the workspace is trusted', () => {
    assert.equal(shouldDeferActivation(true), false);
  });
});

describe('untrustedWorkspaceWarning', () => {
  test('names every restricted setting', () => {
    const message = untrustedWorkspaceWarning();
    for (const setting of RESTRICTED_TRUST_SETTINGS) {
      assert.ok(
        message.includes(setting),
        `expected warning to mention ${setting}: ${message}`,
      );
    }
  });

  test('mentions the extension and that it will not spawn the binary', () => {
    const message = untrustedWorkspaceWarning();
    assert.match(message, /SuperBased/);
    assert.match(message, /not.*spawned|will not.*spawn/i);
  });

  test('restricted settings list is exactly the executable-naming settings', () => {
    assert.deepEqual(RESTRICTED_TRUST_SETTINGS, [
      'observer.binary.path',
      'observer.binary.preferPathBinary',
    ]);
  });
});
