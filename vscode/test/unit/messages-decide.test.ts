// Unit tests for the admin message decisions in src/notifications/decide.ts
// and Client.ackMessage's double-submit confirm flow (T-854).

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { decideAdminMessage, messagesRoute, messagesStatusText } from '../../src/notifications/decide';
import { Client } from '../../src/api/client';
import type { MessagesNewest, MessagesSummaryResponse } from '../../src/api/types';

const surfaces = { toast: true, vscode: true, statusline: true, desktop: false, alerts_only: false, read_receipts: true };

function newest(id: number, over: Partial<MessagesNewest> = {}): MessagesNewest {
  return {
    thread_id: 't1',
    message_id: id,
    subject: 'Opus for lint fixes in payments-api',
    author_name: 'Asha Kim',
    kind: 'coaching',
    created_at: '2026-10-15T14:31:00Z',
    require_ack: true,
    ...over,
  };
}

function summary(over: Partial<MessagesSummaryResponse> = {}): MessagesSummaryResponse {
  return {
    enrolled: true,
    rail: { state: 'ok' },
    unread: 1,
    unread_threads: 1,
    needs_ack: 1,
    unread_alerts: 0,
    failed_outbox: 0,
    newest: null,
    newest_alert: null,
    push: { unread: 1, newest: newest(8) },
    surfaces,
    ...over,
  };
}

describe('decideAdminMessage', () => {
  const rows: { name: string; data: MessagesSummaryResponse | null; last: number; fire: boolean; seen: number }[] = [
    { name: 'no payload', data: null, last: 3, fire: false, seen: 3 },
    { name: 'not enrolled', data: summary({ enrolled: false }), last: 3, fire: false, seen: 3 },
    { name: 'a new message fires', data: summary(), last: 7, fire: true, seen: 8 },
    { name: 'already announced', data: summary(), last: 8, fire: false, seen: 8 },
    { name: 'an older id never re-fires', data: summary(), last: 9, fire: false, seen: 9 },
    { name: 'vscode surface off records only', data: summary({ surfaces: { ...surfaces, vscode: false } }), last: 7, fire: false, seen: 8 },
    { name: 'read before the poll records only', data: summary({ push: { unread: 0, newest: newest(8) } }), last: 7, fire: false, seen: 8 },
    { name: 'nothing to push', data: summary({ push: { unread: 0, newest: null } }), last: 7, fire: false, seen: 7 },
  ];
  for (const r of rows) {
    test(r.name, () => {
      const d = decideAdminMessage(r.data, r.last);
      assert.equal(d.fire, r.fire);
      assert.equal(d.seen, r.seen);
    });
  }

  test('copy names the author, offers Acknowledge only when asked, warns for alerts', () => {
    const d = decideAdminMessage(summary(), 0);
    assert.equal(d.text, 'Message from your admin, Asha Kim: Opus for lint fixes in payments-api. They ask you to acknowledge it.');
    assert.equal(d.canAck, true);
    assert.equal(d.warn, false);
    const alert = decideAdminMessage(summary({ push: { unread: 1, newest: newest(9, { kind: 'alert', require_ack: false, subject: 'Key leaked?' }) } }), 0);
    assert.equal(alert.warn, true);
    assert.equal(alert.canAck, false);
    assert.equal(alert.text, 'Message from your admin, Asha Kim: Key leaked?');
    assert.doesNotMatch(alert.text ?? '', /\b(she|he|her|his)\b/i);
  });
});

describe('messagesStatusText', () => {
  test('shown only while something is unread on an enrolled node with the surface on', () => {
    assert.equal(messagesStatusText(summary()), '1 from admin');
    assert.equal(messagesStatusText(summary({ push: { unread: 120, newest: null } })), '99+ from admin');
    assert.equal(messagesStatusText(summary({ push: { unread: 0, newest: null } })), null);
    assert.equal(messagesStatusText(summary({ surfaces: { ...surfaces, vscode: false } })), null);
    assert.equal(messagesStatusText(summary({ enrolled: false })), null);
    assert.equal(messagesStatusText(null), null);
  });
});

describe('messagesRoute', () => {
  test('opens the page or one conversation', () => {
    assert.equal(messagesRoute(), '/messages');
    assert.equal(messagesRoute('t 1/x'), '/messages?thread=t%201%2Fx');
  });
});

describe('Client.ackMessage', () => {
  test('mints the confirm token with a GET, then echoes it in header and cookie', async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const fakeFetch: typeof fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ confirm_token: 'a'.repeat(64) }), { status: 200 });
      }
      return new Response(JSON.stringify({ message: { id: 42 } }), { status: 200 });
    };
    const c = new Client({ dashboardPort: 8081, fetchImpl: fakeFetch });
    await c.ackMessage(42);
    assert.equal(calls.length, 2);
    assert.equal(calls[0]!.url, 'http://127.0.0.1:8081/api/messages?status=open');
    assert.equal(calls[1]!.url, 'http://127.0.0.1:8081/api/messages/42/ack');
    const h = calls[1]!.init?.headers as Record<string, string>;
    assert.equal(calls[1]!.init?.method, 'POST');
    assert.equal(h['Content-Type'], 'application/json');
    assert.equal(h['X-Observer-Confirm'], 'a'.repeat(64));
    assert.equal(h.Cookie, `sb_remote_confirm=${'a'.repeat(64)}`);
  });

  test('throws when the daemon refuses, so the caller opens the thread instead', async () => {
    let n = 0;
    const fakeFetch: typeof fetch = async () => {
      n++;
      if (n === 1) return new Response(JSON.stringify({ confirm_token: 'tok' }), { status: 200 });
      return new Response('nope', { status: 409, statusText: 'Conflict' });
    };
    const c = new Client({ dashboardPort: 8081, fetchImpl: fakeFetch });
    await assert.rejects(() => c.ackMessage(7), /HTTP 409/);
  });

  test('refuses a bad id and a missing token without posting', async () => {
    let n = 0;
    const fakeFetch: typeof fetch = async () => {
      n++;
      return new Response(JSON.stringify({}), { status: 200 });
    };
    const c = new Client({ dashboardPort: 8081, fetchImpl: fakeFetch });
    await assert.rejects(() => c.ackMessage(0), /invalid message id/);
    assert.equal(n, 0);
    await assert.rejects(() => c.ackMessage(5), /no confirm token/);
    assert.equal(n, 1);
  });
});
