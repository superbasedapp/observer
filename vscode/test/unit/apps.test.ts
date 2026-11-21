// Unit tests for src/apps-internals.ts (lane POLISH-F2): "SuperBased: Turn
// on AI Apps" calls the daemon's one enable seam, refuses an edition without
// AI Apps with the reinstall line, never says "on" unless the receiver
// listens, and tells an older daemon to restart without restarting it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  NO_SEAM,
  REINSTALL_FIX,
  classifyEnable,
  consentText,
  refusalFor,
  runEnable,
  type AppsStatusLite,
  type AppsTransport,
  type EnableReportLite,
} from '../../src/apps-internals';

const offStatus: AppsStatusLite = {
  in_build: true,
  component: 'available',
  on: false,
  receiver: { state: 'not_running' },
  consent: { sentence: 'Stays on this machine.', receiver_note: '(this machine only)' },
  confirm_token: 'tok',
};

const onReport: EnableReportLite = {
  outcome: 'on',
  ok: true,
  message: 'AI Apps is on.',
  receiver: { state: 'listening', http_addr: '127.0.0.1:4318' },
};

/** fake records the calls and answers from the given pairs. */
function fake(
  status: [number, AppsStatusLite | undefined],
  enable: [number, EnableReportLite | undefined] = [200, onReport],
): AppsTransport & { tokens: string[] } {
  const tokens: string[] = [];
  return {
    tokens,
    status: async () => status,
    enable: async (token) => {
      tokens.push(token);
      return enable;
    },
  };
}

const yes = async (): Promise<boolean> => true;

describe('Turn on AI Apps', () => {
  test('on: calls the seam with the confirm token after asking, and offers the AI Apps page', async () => {
    const t = fake([200, offStatus]);
    let asked = '';
    const out = await runEnable(t, async (text) => {
      asked = text;
      return true;
    });
    assert.deepEqual(t.tokens, ['tok']);
    assert.equal(out?.kind, 'on');
    assert.equal(out?.openApps, true);
    assert.match(out!.message, /listening on 127\.0\.0\.1:4318 \(this machine only\)/);
    assert.match(asked, /adds the AI Apps component/);
    assert.match(asked, /Stays on this machine\./);
    assert.match(asked, /takes effect at the next start/);
  });

  test('declining changes nothing', async () => {
    const t = fake([200, offStatus]);
    assert.equal(await runEnable(t, async () => false), undefined);
    assert.deepEqual(t.tokens, []);
  });

  test('an edition without AI Apps refuses with the reinstall line, before asking', async () => {
    for (const st of [
      { ...offStatus, in_build: false },
      { ...offStatus, component: 'absent' },
    ]) {
      const t = fake([200, st]);
      const out = await runEnable(t, async () => assert.fail('asked'));
      assert.equal(out?.kind, 'refused');
      assert.match(out!.message, /does not include AI Apps/);
      assert.equal(out!.fix, REINSTALL_FIX);
      assert.deepEqual(t.tokens, []);
    }
    assert.equal(refusalFor({ ...offStatus, component: 'blocked' })?.kind, 'refused');
    assert.equal(refusalFor(offStatus), undefined);
  });

  test('a bind failure is an error with the fix, never "on"', async () => {
    const bind: EnableReportLite = {
      outcome: 'bind_failed',
      ok: false,
      message: 'AI Apps is set to on, but the receiver could not listen on 127.0.0.1:4318: address already in use',
      fix: 'Another program holds the port (a collector or Jaeger is common). Stop it, or move the receiver with [ingest.otel] http_addr / grpc_addr, then turn AI Apps on again.',
      receiver: { state: 'bind_failed', http_addr: '127.0.0.1:4318' },
    };
    const out = await runEnable(fake([200, offStatus], [409, bind]), yes);
    assert.equal(out?.kind, 'failed');
    assert.equal(out?.openApps, false);
    assert.match(out!.message, /could not listen/);
    assert.match(out!.fix, /\[ingest\.otel\] http_addr/);
  });

  test('an older daemon (404) or one without the seam (501) gets restart-to-finish', async () => {
    assert.equal(await runEnable(fake([404, undefined]), yes), NO_SEAM);
    assert.equal(await runEnable(fake([200, offStatus], [501, undefined]), yes), NO_SEAM);
    assert.match(NO_SEAM.fix, /Restart `observer start` to finish/);
  });

  test('already on answers at once, without asking', async () => {
    const st = { ...offStatus, component: 'active', on: true, receiver: { state: 'listening', http_addr: '127.0.0.1:4318' } };
    const t = fake([200, st]);
    const out = await runEnable(t, async () => assert.fail('asked'));
    assert.equal(out?.kind, 'already_on');
    assert.deepEqual(t.tokens, []);
  });

  test('every outcome row: classifyEnable', () => {
    const cases: Array<[number, EnableReportLite | undefined, string]> = [
      [200, onReport, 'on'],
      [409, { outcome: 'not_in_build', message: 'x' }, 'refused'],
      [409, { outcome: 'blocked', message: 'x' }, 'refused'],
      [409, { outcome: 'refused', message: 'x' }, 'refused'],
      [500, { outcome: 'config_failed', message: 'x' }, 'failed'],
      [504, { outcome: 'receiver_no_answer', message: 'x' }, 'failed'],
      [403, undefined, 'failed'],
      [404, undefined, 'restart'],
      [501, undefined, 'restart'],
      // ok without the on outcome is never "on".
      [200, { outcome: 'receiver_no_answer', ok: true }, 'failed'],
    ];
    for (const [code, rep, kind] of cases) {
      assert.equal(classifyEnable(code, rep, undefined).kind, kind, `${code} ${rep?.outcome}`);
    }
    const pending = classifyEnable(200, { ...onReport, pending_next_start: ['alerts'] }, undefined);
    assert.match(pending.message, /next start of the daemon: alerts/);
  });

  test('the consent text drops the component line once it is active', () => {
    assert.doesNotMatch(consentText({ ...offStatus, component: 'active' }), /adds the AI Apps component/);
    assert.match(consentText({ ...offStatus, consent: { sentence: 'Also sent to Acme (summaries).' } }), /Also sent to Acme/);
  });
});
