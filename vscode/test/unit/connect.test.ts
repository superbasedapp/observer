// Unit tests for src/connect-internals.ts ("SuperBased: Sign in and connect",
// the account status bar item and the first-run nudge; Getting started v2).
//
// connect.ts and connectStatus.ts import `vscode`, which is not resolvable
// under the plain-node runner, so their decisions are exercised through the
// pure helpers. runConnectProcess is driven with a fake child process that
// replays `observer connect --json` lines (contract B).

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import type { ChildProcess } from 'node:child_process';
import {
  CONNECT_STATUS_PATH,
  NUDGE_MAX_SHOWS,
  NUDGE_REPEAT_MS,
  NUDGE_RULES,
  connectArgs,
  connectItem,
  connectedText,
  decideNudge,
  errorText,
  fetchConnectStatus,
  isSafeOpenURL,
  lineSplitter,
  nudgeShown,
  parseConnectLine,
  progressMessage,
  runConnectProcess,
  safeDisplayName,
  validateTeam,
  waitingMessage,
  type ConnectEvent,
  type ConnectStatus,
  type NudgeState,
} from '../../src/connect-internals';

const LOCAL: ConnectStatus = {
  sentence: 'This machine keeps its data on this machine.',
  kind: 'local',
  signed_in: false,
  identity_known: true,
  locked: false,
};

describe('parseConnectLine', () => {
  test('reads every contract B state', () => {
    assert.deepEqual(
      parseConnectLine(
        '{"state":"waiting_approval","approve_url":"https://cloud.superbased.app/connect/r1","verify_url":"https://cloud.superbased.app/connect","user_code":"KTRW-4821"}',
      ),
      {
        state: 'waiting_approval',
        approve_url: 'https://cloud.superbased.app/connect/r1',
        verify_url: 'https://cloud.superbased.app/connect',
        user_code: 'KTRW-4821',
      },
    );
    assert.deepEqual(parseConnectLine('{"state":"approved","target":{"slug":"acme","kind":"team"}}'), {
      state: 'approved',
      target: { slug: 'acme', kind: 'team' },
    });
    assert.deepEqual(parseConnectLine('{"state":"approved","target":null}'), { state: 'approved', target: null });
    assert.deepEqual(parseConnectLine('{"state":"attaching"}'), { state: 'attaching' });
    assert.deepEqual(
      parseConnectLine('{"state":"connected","display_name":"Acme","kind":"team","online_url":"https://acme.superbased.app/"}'),
      { state: 'connected', display_name: 'Acme', kind: 'team', online_url: 'https://acme.superbased.app/' },
    );
    assert.deepEqual(parseConnectLine('{"state":"signed_in_only"}'), { state: 'signed_in_only' });
    assert.deepEqual(parseConnectLine('{"state":"error","code":"expired","message":"request expired"}'), {
      state: 'error',
      code: 'expired',
      message: 'request expired',
    });
  });

  test('drops non-JSON, broken JSON and unknown states', () => {
    assert.equal(parseConnectLine('Opening your browser...'), null);
    assert.equal(parseConnectLine('{"state":'), null);
    assert.equal(parseConnectLine('{"state":"something_new"}'), null);
    assert.equal(parseConnectLine('[1,2]'), null);
  });
});

describe('connectArgs and validateTeam', () => {
  test('personal run has no positional', () => {
    assert.deepEqual(connectArgs(), ['connect', '--json', '--no-browser']);
    assert.deepEqual(connectArgs('  '), ['connect', '--json', '--no-browser']);
  });
  test('a team is normalised and appended', () => {
    assert.deepEqual(connectArgs(' Acme-Dev '), ['connect', '--json', '--no-browser', 'acme-dev']);
  });
  test('a flag-shaped or odd team is never passed', () => {
    assert.deepEqual(connectArgs('--server=evil'), ['connect', '--json', '--no-browser']);
    assert.deepEqual(connectArgs('a b'), ['connect', '--json', '--no-browser']);
    assert.ok(validateTeam('-x'));
    assert.ok(validateTeam('acme/dev'));
    assert.ok(validateTeam(''));
    assert.equal(validateTeam('acme-dev'), undefined);
  });
});

describe('wording', () => {
  test('waiting message carries the code', () => {
    assert.equal(waitingMessage('KTRW-4821'), 'Waiting for approval in your browser, code KTRW-4821');
    assert.equal(waitingMessage(''), 'Waiting for approval in your browser');
  });
  test('progress for each in-flight state', () => {
    const cases: Array<[ConnectEvent, string | undefined]> = [
      [{ state: 'waiting_approval', approve_url: '', verify_url: '', user_code: 'AB-1' }, 'Waiting for approval in your browser, code AB-1'],
      [{ state: 'approved', target: { slug: 'acme' } }, 'Approved. Connecting this machine...'],
      [{ state: 'approved', target: null }, 'Approved. Finishing sign-in...'],
      [{ state: 'attaching' }, 'Connecting this machine...'],
      [{ state: 'signed_in_only' }, undefined],
    ];
    for (const [ev, want] of cases) assert.equal(progressMessage(ev), want, ev.state);
  });
  test('known error codes read in plain words, unknown fall back to the message', () => {
    assert.match(errorText('expired', 'x'), /expired/);
    assert.match(errorText('declined', ''), /Nothing was sent/);
    assert.match(errorText('unsupported_binary', ''), /Update it/);
    assert.equal(errorText('weird', 'the server said no'), 'Could not sign in: the server said no');
    assert.match(errorText('weird', ''), /output/);
  });
  test('no em dash in user copy', () => {
    const texts = [errorText('expired', ''), connectedText('Acme', 'team'), waitingMessage('X')];
    for (const t of texts) assert.ok(!t.includes('—'), t);
  });
});

describe('safeDisplayName', () => {
  test('never shows a personal dashboard address', () => {
    assert.equal(safeDisplayName('u-7f3k2.superbased.app', 'personal'), 'your personal dashboard');
    assert.equal(safeDisplayName('https://u-7f3k2.superbased.app/', 'individual'), 'your personal dashboard');
    assert.equal(safeDisplayName('u-7f3k2', 'personal'), 'your personal dashboard');
    assert.equal(safeDisplayName('', 'team'), 'your team');
  });
  test('keeps a real name', () => {
    assert.equal(safeDisplayName('Acme Dev', 'team'), 'Acme Dev');
    assert.equal(safeDisplayName("Sam's dashboard", 'personal'), "Sam's dashboard");
  });
});

describe('isSafeOpenURL', () => {
  test('https and loopback http only', () => {
    assert.ok(isSafeOpenURL('https://cloud.superbased.app/connect/r1'));
    assert.ok(isSafeOpenURL('http://127.0.0.1:8899/connect/r1'));
    assert.ok(!isSafeOpenURL('http://cloud.superbased.app/connect/r1'));
    assert.ok(!isSafeOpenURL('file:///etc/passwd'));
    assert.ok(!isSafeOpenURL('command:workbench.action.terminal.new'));
    assert.ok(!isSafeOpenURL('https://user:pw@cloud.superbased.app/'));
    assert.ok(!isSafeOpenURL(''));
    assert.ok(!isSafeOpenURL('not a url'));
  });
});

describe('NUDGE_RULES (one case per row)', () => {
  const now = 1_800_000_000_000;
  const cases: Array<{ rule: string; state?: NudgeState; status: ConnectStatus | null; show: boolean }> = [
    { rule: 'status unknown', status: null, show: false },
    { rule: 'set by company', status: { ...LOCAL, locked: true }, show: false },
    { rule: 'sign-in state unreadable', status: { ...LOCAL, identity_known: false }, show: false },
    { rule: 'signed in', status: { ...LOCAL, signed_in: true }, show: false },
    { rule: 'machine connected', status: { ...LOCAL, kind: 'managed' }, show: false },
    { rule: 'user chose sign in', state: { shown: 1, lastShownAt: 0, done: true }, status: LOCAL, show: false },
    { rule: 'shown enough', state: { shown: NUDGE_MAX_SHOWS, lastShownAt: 0 }, status: LOCAL, show: false },
    { rule: 'first activation', status: LOCAL, show: true },
    { rule: 'seven days after later', state: { shown: 1, lastShownAt: now - NUDGE_REPEAT_MS }, status: LOCAL, show: true },
    { rule: 'within seven days of later', state: { shown: 1, lastShownAt: now - NUDGE_REPEAT_MS + 1 }, status: LOCAL, show: false },
  ];
  test('every row has a case', () => {
    assert.deepEqual(
      cases.map((c) => c.rule),
      NUDGE_RULES.map((r) => r.name),
    );
  });
  for (const c of cases) {
    test(c.rule, () => {
      assert.deepEqual(decideNudge(c.state, c.status, now), { show: c.show, rule: c.rule });
    });
  }
  test('shown at most twice in a lifetime', () => {
    let state: NudgeState | undefined;
    let t = now;
    let shows = 0;
    for (let i = 0; i < 10; i++) {
      if (decideNudge(state, LOCAL, t).show) {
        state = nudgeShown(state, t);
        shows++;
      }
      t += NUDGE_REPEAT_MS;
    }
    assert.equal(shows, NUDGE_MAX_SHOWS);
  });
});

describe('connectItem', () => {
  test('hidden while unknown', () => {
    assert.equal(connectItem(null).visible, false);
    assert.equal(connectItem({ ...LOCAL, identity_known: false }).visible, false);
  });
  test('not signed in: click signs in and connects', () => {
    const m = connectItem(LOCAL);
    assert.equal(m.text, '$(account) SuperBased · not signed in');
    assert.deepEqual(m.action, { kind: 'connect' });
  });
  test('signed in only: click connects', () => {
    const m = connectItem({ ...LOCAL, signed_in: true });
    assert.equal(m.text, '$(account) SuperBased · signed in');
    assert.deepEqual(m.action, { kind: 'connect' });
  });
  test('connected with an online URL from the daemon', () => {
    const m = connectItem({ ...LOCAL, kind: 'managed', signed_in: true, destination: 'Acme', online_url: 'https://acme.superbased.app/' });
    assert.equal(m.text, '$(account) SuperBased · Acme');
    assert.deepEqual(m.action, { kind: 'open', url: 'https://acme.superbased.app/' });
    assert.ok(!m.tooltip.includes('superbased.app'), 'the address is never printed');
  });
  test('connected personal: remembered URL, never the u- address in text', () => {
    const m = connectItem(
      { ...LOCAL, kind: 'individual', signed_in: true, destination: 'u-7f3k2.superbased.app' },
      { onlineUrl: 'https://u-7f3k2.superbased.app/' },
    );
    assert.equal(m.text, '$(account) SuperBased · your personal dashboard');
    assert.deepEqual(m.action, { kind: 'open', url: 'https://u-7f3k2.superbased.app/' });
    assert.ok(!m.tooltip.includes('u-7f3k2'));
  });
  test('connected without a safe URL opens the local dashboard', () => {
    const m = connectItem({ ...LOCAL, kind: 'managed', destination: 'Acme', online_url: 'http://acme.example/' });
    assert.deepEqual(m.action, { kind: 'dashboard' });
  });
});

describe('fetchConnectStatus', () => {
  const respond = (status: number, body: unknown = {}): typeof fetch =>
    (async () => new Response(JSON.stringify(body), { status })) as typeof fetch;
  test('404 and 501 resolve to null', async () => {
    assert.equal(await fetchConnectStatus(`http://127.0.0.1:1${CONNECT_STATUS_PATH}`, respond(404), 1000), null);
    assert.equal(await fetchConnectStatus(`http://127.0.0.1:1${CONNECT_STATUS_PATH}`, respond(501), 1000), null);
  });
  test('500 throws, 200 parses', async () => {
    await assert.rejects(fetchConnectStatus('http://x', respond(500), 1000));
    assert.deepEqual(await fetchConnectStatus('http://x', respond(200, LOCAL), 1000), LOCAL);
  });
});

describe('lineSplitter', () => {
  test('joins chunks and handles CRLF and a trailing partial line', () => {
    const got: string[] = [];
    const s = lineSplitter((l) => got.push(l));
    s.push('{"state":"att');
    s.push('aching"}\r\n\n{"state":"signed');
    s.push('_in_only"}');
    s.flush();
    assert.deepEqual(got, ['{"state":"attaching"}', '{"state":"signed_in_only"}']);
  });
});

/** fakeChild replays stdout/stderr lines then exits with code. */
function fakeChild(stdout: string[], stderr: string[], code: number): { child: ChildProcess; killed: () => boolean } {
  const ee = new EventEmitter() as unknown as ChildProcess & EventEmitter;
  const out = new PassThrough();
  const err = new PassThrough();
  let killed = false;
  Object.assign(ee, {
    stdout: out,
    stderr: err,
    kill: () => {
      killed = true;
      setImmediate(() => ee.emit('close', null));
      return true;
    },
  });
  setImmediate(() => {
    for (const l of stdout) out.write(`${l}\n`);
    for (const l of stderr) err.write(`${l}\n`);
    if (code >= 0) setImmediate(() => ee.emit('close', code));
  });
  return { child: ee, killed: () => killed };
}

describe('runConnectProcess', () => {
  test('connected: events in order, the binary gets the contract argv', async () => {
    const events: string[] = [];
    let argv: string[] = [];
    const { child } = fakeChild(
      [
        '{"state":"waiting_approval","approve_url":"https://cloud.superbased.app/connect/r1","verify_url":"https://cloud.superbased.app/connect","user_code":"KTRW-4821"}',
        '{"state":"approved","target":{"slug":"acme","kind":"team","display_name":"Acme"}}',
        '{"state":"attaching"}',
        '{"state":"connected","display_name":"Acme","kind":"team","online_url":"https://acme.superbased.app/"}',
      ],
      [],
      0,
    );
    const out = await runConnectProcess('/bin/observer', 'acme', {
      spawn: (_f, a) => {
        argv = a;
        return child;
      },
      onEvent: (ev) => events.push(ev.state),
      onLog: () => undefined,
    });
    assert.deepEqual(argv, ['connect', '--json', '--no-browser', 'acme']);
    assert.deepEqual(events, ['waiting_approval', 'approved', 'attaching', 'connected']);
    assert.deepEqual(out, { kind: 'connected', displayName: 'Acme', targetKind: 'team', onlineUrl: 'https://acme.superbased.app/' });
  });

  test('Not now on the approval page: signed in only', async () => {
    const { child } = fakeChild(['{"state":"approved","target":null}', '{"state":"signed_in_only"}'], [], 0);
    const out = await runConnectProcess('/bin/observer', undefined, { spawn: () => child, onEvent: () => undefined, onLog: () => undefined });
    assert.deepEqual(out, { kind: 'signed_in_only' });
  });

  test('error line wins over the exit code', async () => {
    const { child } = fakeChild(['{"state":"error","code":"expired","message":"request expired"}'], [], 1);
    const out = await runConnectProcess('/bin/observer', undefined, { spawn: () => child, onEvent: () => undefined, onLog: () => undefined });
    assert.deepEqual(out, { kind: 'error', code: 'expired', message: 'request expired' });
  });

  test('an older binary without --json reads as unsupported', async () => {
    const logs: string[] = [];
    const { child } = fakeChild([], ['Error: unknown flag: --json'], 1);
    const out = await runConnectProcess('/bin/observer', undefined, { spawn: () => child, onEvent: () => undefined, onLog: (l) => logs.push(l) });
    assert.deepEqual(out, { kind: 'error', code: 'unsupported_binary', message: '' });
    assert.deepEqual(logs, ['Error: unknown flag: --json']);
  });

  test('a silent non-zero exit names the code', async () => {
    const { child } = fakeChild(['plain text line'], [], 3);
    const out = await runConnectProcess('/bin/observer', undefined, { spawn: () => child, onEvent: () => undefined, onLog: () => undefined });
    assert.deepEqual(out, { kind: 'error', code: 'exit', message: 'observer exited with code 3' });
  });

  test('cancel kills the child and resolves cancelled', async () => {
    const { child, killed } = fakeChild(['{"state":"waiting_approval","approve_url":"","verify_url":"","user_code":"AB"}'], [], -1);
    const ac = new AbortController();
    const p = runConnectProcess('/bin/observer', undefined, {
      spawn: () => child,
      signal: ac.signal,
      onEvent: (ev) => {
        if (ev.state === 'waiting_approval') ac.abort();
      },
      onLog: () => undefined,
    });
    assert.deepEqual(await p, { kind: 'cancelled' });
    assert.ok(killed());
  });

  test('a spawn that throws is an error, not a crash', async () => {
    const out = await runConnectProcess('/missing', undefined, {
      spawn: () => {
        throw new Error('ENOENT');
      },
      onEvent: () => undefined,
      onLog: () => undefined,
    });
    assert.deepEqual(out, { kind: 'error', code: 'spawn_failed', message: 'ENOENT' });
  });

  test('the hard timeout stops a run', async () => {
    const { child, killed } = fakeChild([], [], -1);
    const out = await runConnectProcess('/bin/observer', undefined, {
      spawn: () => child,
      timeoutMs: 20,
      onEvent: () => undefined,
      onLog: () => undefined,
    });
    assert.deepEqual(out, { kind: 'error', code: 'timeout', message: '' });
    assert.ok(killed());
  });
});
