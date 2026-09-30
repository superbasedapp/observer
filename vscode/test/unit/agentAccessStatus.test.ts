// Unit tests for src/agentAccessStatus-internals.ts (the "MCP access" status
// bar item, Agent Access P10).
//
// Fixture-driven: test/fixtures/agentAccess/*.json are REAL daemon payloads
// of GET /api/mcp-access/status, generated from cmd/observer's
// buildMCPAccessView and pinned to the Go wire shape by
// TestMCPAccessView_FixturesMatchGoShape (and unavailable.json by
// TestMCPAccessUnavailableMatchesFixture), so these tests cannot drift from
// what the daemon actually serves.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  MCP_ACCESS_PATH,
  MCP_ACCESS_POLL_MS,
  agentAccessItem,
  agentAccessQuickPick,
  coverageSummary,
  effectiveSummary,
  fetchAgentAccessStatus,
  isSafeExternalURL,
  type AgentAccessResponse,
  type AgentAccessView,
} from '../../src/agentAccessStatus-internals';

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'agentAccess');

function fixture(name: string): AgentAccessResponse {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf8')) as AgentAccessResponse;
}

function view(name: string): AgentAccessView {
  const f = fixture(name);
  assert.equal(f.available, true, `${name} is a served view`);
  return f as AgentAccessView;
}

describe('agentAccessItem (fixtures)', () => {
  test('hidden: older daemon, no relay seam, relay disabled, not enrolled', () => {
    const cases: [AgentAccessResponse | null, RegExp][] = [
      [null, /older build/],
      [fixture('unavailable'), /served by the observer daemon/],
      [fixture('disabled'), /relay is disabled/],
      [fixture('unenrolled'), /not enrolled/],
    ];
    for (const [resp, why] of cases) {
      const m = agentAccessItem(resp);
      assert.equal(m.visible, false);
      assert.match(m.hiddenReason ?? '', why);
      assert.equal(m.text, '');
    }
  });

  test('enabled + effective: plug icon, approved-server count, honest tooltip', () => {
    const m = agentAccessItem(fixture('enabled'));
    assert.equal(m.visible, true);
    assert.equal(m.warning, false);
    assert.equal(m.text, '$(plug) MCP 1');
    const tip = m.tooltip.join('\n');
    assert.match(tip, /Relay: on \(stdio_wrapper, audit async\), point effective/);
    assert.match(tip, /Approved servers: 1 in 1 virtual server\b/);
    assert.match(tip, /Coverage: 4 of 114 cells relay-governed, 62 best-effort, 46 ungoverned, 2 planned/);
    assert.match(tip, /Effective state: effective, enforcing \(grant v3\)/);
    assert.match(tip, /Remote forwarding: off - no agent-access key/);
    assert.match(tip, /1 server\(s\) need your own sign-in/);
  });

  test('enabled but ineffective point: warning icon + missing capability named', () => {
    const m = agentAccessItem(fixture('ineffective'));
    assert.equal(m.visible, true);
    assert.equal(m.warning, true);
    assert.equal(m.text, '$(warning) MCP 1');
    const tip = m.tooltip.join('\n');
    assert.match(tip, /point ineffective - missing projection.applied/);
    assert.match(tip, /Coverage: 0 of 114 cells relay-governed/);
    // An ineffective point never ACKs "effective" (doc3 §12.7, Lane SURF F1).
    assert.match(tip, /Effective state: accepted inert - mode observe/);
    assert.doesNotMatch(tip, /Effective state: effective/);
  });

  test('a broken record chain or an unbound daemon relay is a warning', () => {
    const broken = view('enabled');
    broken.status = { ...broken.status, chain_head: 3, chain_ok: false };
    const m = agentAccessItem(broken);
    assert.equal(m.warning, true);
    assert.match(m.tooltip.join('\n'), /chain BROKEN - run `observer mcp doctor`/);
    const unbound = { ...view('enabled'), daemon_relay: false };
    const u = agentAccessItem(unbound);
    assert.equal(u.warning, true);
    assert.match(u.tooltip.join('\n'), /restart it to bind the relay/);
  });
});

describe('agentAccessQuickPick (fixtures)', () => {
  test('a per-user server connects in the org dashboard, last entry opens the dashboard', () => {
    const entries = agentAccessQuickPick(view('enabled'));
    assert.equal(entries.length, 2);
    assert.equal(entries[0].label, '$(key) gh');
    assert.equal(entries[0].description, 'github - per-user sign-in');
    assert.deepEqual(entries[0].action, { kind: 'connect', url: 'https://org.acme:9443/agent-access/connections' });
    assert.match(entries[0].detail ?? '', /never sees the token/);
    assert.deepEqual(entries[1].action, { kind: 'dashboard' });
  });

  test('no connect URL (not enrolled): the per-user entry says why and does nothing', () => {
    const entries = agentAccessQuickPick(view('unenrolled'));
    assert.deepEqual(entries[0].action, { kind: 'none' });
    assert.match(entries[0].detail ?? '', /not enrolled with an organization/);
  });

  test('a service-credentialed server is listed with its mode, no connect', () => {
    const v = view('enabled');
    v.vservers = [{ id: 'vs-x', slug: 'fs', servers: [{ id: 'fs', target: 'stdio:fs', credential_mode: 'service', pinned: true, per_user_connect: false }] }];
    const entries = agentAccessQuickPick(v);
    assert.equal(entries[0].label, '$(server) fs');
    assert.equal(entries[0].description, 'fs - service');
    assert.equal(entries[0].detail, 'stdio:fs, tool snapshot pinned');
    assert.deepEqual(entries[0].action, { kind: 'none' });
  });

  test('an unsafe connect URL is never offered', () => {
    const v = view('enabled');
    v.connect = { url: 'javascript:alert(1)' };
    assert.deepEqual(agentAccessQuickPick(v)[0].action, { kind: 'none' });
  });

  test('no approved servers: one honest entry plus the dashboard', () => {
    const v = view('enabled');
    v.vservers = [];
    const entries = agentAccessQuickPick(v);
    assert.equal(entries.length, 2);
    assert.equal(entries[0].label, '$(info) No approved MCP servers');
  });
});

describe('wording helpers', () => {
  test('coverageSummary never invents a label; empty = nothing measured', () => {
    assert.equal(coverageSummary({}), 'no coverage measured');
    assert.equal(coverageSummary({ mediated: 2, uncovered: 2 }), '2 of 4 cells relay-governed, 0 best-effort, 2 ungoverned');
  });

  test('effectiveSummary: one case per status class', () => {
    const e = (status: string, reason: string, mode: string, v = 0) => ({ status, reason, mode, running_version: v, restart_required: false });
    assert.equal(effectiveSummary(e('effective', 'ok', 'enforce', 3)), 'effective, enforcing (grant v3)');
    assert.equal(effectiveSummary(e('effective', 'ok', 'observe', 3)), 'effective, observe only (not enforcing) (grant v3)');
    assert.equal(effectiveSummary(e('none', 'no_policy', 'off')), 'no grant in force');
    assert.equal(effectiveSummary(e('accepted_inert', 'not_preauthorized', 'observe', 4)), 'accepted inert - not preauthorized');
  });

  test('isSafeExternalURL admits absolute http(s) only', () => {
    assert.equal(isSafeExternalURL('https://org.acme/agent-access/connections'), true);
    assert.equal(isSafeExternalURL('http://127.0.0.1:9443/x'), true);
    assert.equal(isSafeExternalURL('javascript:alert(1)'), false);
    assert.equal(isSafeExternalURL('file:///etc/passwd'), false);
    assert.equal(isSafeExternalURL('/relative'), false);
    assert.equal(isSafeExternalURL(undefined), false);
  });

  test('poll cadence is never faster than the cost bar (60 s)', () => {
    assert.ok(MCP_ACCESS_POLL_MS >= 60_000);
  });
});

describe('fetchAgentAccessStatus', () => {
  const mkFetch = (status: number, body: unknown, seen: string[]): typeof fetch =>
    (async (input: string | URL | Request) => {
      seen.push(String(input));
      return new Response(JSON.stringify(body), { status, statusText: status === 200 ? 'OK' : 'ERR' });
    }) as typeof fetch;

  test('200 decodes the payload from the route', async () => {
    const seen: string[] = [];
    const got = await fetchAgentAccessStatus(`http://127.0.0.1:8081${MCP_ACCESS_PATH}`, mkFetch(200, fixture('enabled'), seen), 1_000);
    assert.equal(seen[0], 'http://127.0.0.1:8081/api/mcp-access/status');
    assert.equal(got?.available, true);
  });

  test('404 (older daemon) resolves to null, the item stays hidden', async () => {
    const got = await fetchAgentAccessStatus('http://x/api/mcp-access/status', mkFetch(404, {}, []), 1_000);
    assert.equal(got, null);
    assert.equal(agentAccessItem(got).visible, false);
  });

  test('500 throws with the status', async () => {
    await assert.rejects(
      fetchAgentAccessStatus('http://x/api/mcp-access/status', mkFetch(500, { error: 'boom' }, []), 1_000),
      /HTTP 500/,
    );
  });
});
