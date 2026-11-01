import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ackPrompt,
  addAttachment,
  attachmentLink,
  attachmentView,
  budgetAttachOptions,
  checkDraft,
  decideToast,
  initials,
  isSendShortcut,
  MESSAGES_CONFIG_DEFAULTS,
  messagesConfigFrom,
  SETTINGS_MESSAGES_LINK,
  SURFACE_SETTINGS,
  surfaceSwitch,
  surfacesDirty,
  kindView,
  listRows,
  listTime,
  MAX_ATTACHMENTS,
  navBadge,
  offeredTopics,
  outboxView,
  pageState,
  pendingAck,
  projectOptions,
  railBanner,
  readReceiptNote,
  requestInit,
  requestLinkFor,
  sendErrorText,
  sessionLink,
  sessionOptions,
  showMessagesNav,
  threadLink,
  toastKicker,
  toastTitle,
  unsentPosts,
  type InboxMessage,
  type MessagesSummaryResponse,
  type OutboxItem,
  type ThreadSummary,
} from "./adminMessages.ts";

const surfaces = { toast: true, vscode: true, statusline: true, desktop: false, alerts_only: false, read_receipts: true };

function summary(over: Partial<MessagesSummaryResponse> = {}): MessagesSummaryResponse {
  return {
    enrolled: true,
    rail: { state: "ok" },
    unread: 0,
    unread_threads: 0,
    needs_ack: 0,
    unread_alerts: 0,
    failed_outbox: 0,
    newest: null,
    newest_alert: null,
    push: { unread: 0, newest: null },
    surfaces,
    ...over,
  };
}

const newest = (id: number, thread = "t1") => ({
  thread_id: thread,
  message_id: id,
  subject: "Opus for lint fixes",
  author_name: "Asha Kim",
  kind: "coaching",
  created_at: "2026-10-15T14:31:00Z",
  require_ack: true,
});

function thread(over: Partial<ThreadSummary> = {}): ThreadSummary {
  return {
    id: "t1",
    subject: "Opus for lint fixes",
    kind: "coaching",
    started_by: "admin",
    status: "open",
    updated_at: "2026-10-15T14:32:00Z",
    last_author_kind: "admin",
    last_author_name: "Asha Kim",
    last_preview: "Hi Priya",
    last_at: "2026-10-15T14:32:00Z",
    messages: 1,
    unread: 1,
    needs_ack: 1,
    pending: 0,
    failed: 0,
    ...over,
  };
}

function msg(over: Partial<InboxMessage> = {}): InboxMessage {
  return {
    id: 1,
    thread_id: "t1",
    author_kind: "admin",
    author_name: "Asha Kim",
    body: "hello",
    require_ack: false,
    created_at: "2026-10-15T14:31:00Z",
    attachments: [],
    received_at: "2026-10-15T14:31:05Z",
    ...over,
  };
}

function outbox(over: Partial<OutboxItem> = {}): OutboxItem {
  return { id: "c1", kind: "post", attachments: [], created_at: "2026-10-15T15:06:00Z", state: "queued", attempts: 0, ...over };
}

test("attachmentLink deep links every attachment type into the node's own pages", () => {
  const cases: [string, string, string][] = [
    ["session", "s-123", "/sessions?session=s-123"],
    ["turn", "s-123#msg_abc", "/sessions?session=s-123&dtab=messages&msg=msg_abc"],
    ["turn", "s-123", "/sessions?session=s-123"],
    ["model", "claude-opus-4-8", "/cost?tab=by-model"],
    ["guard_event", "g1", "/security?tab=verdicts"],
    ["project", "42", "/projects?project=42"],
    ["project", "/home/dev/payments-api", "/projects?root=%2Fhome%2Fdev%2Fpayments-api"],
    ["budget", "b-1", "/cost?tab=budgets"],
    ["request", "17", "/requests"],
    ["mystery", "x", "/messages"],
  ];
  for (const [type, ref, want] of cases) {
    assert.equal(attachmentLink({ type, ref }), want, `${type} ${ref}`);
  }
});

test("sessionLink encodes ids and carries the message key in msg", () => {
  assert.equal(sessionLink("a b"), "/sessions?session=a+b");
  assert.equal(sessionLink("s", "k:1/2"), "/sessions?session=s&dtab=messages&msg=k%3A1%2F2");
});

test("attachmentView prefers the label and excerpt, else plain fallbacks", () => {
  const v = attachmentView({ type: "turn", ref: "s-1#m", label: "Your prompt 12", excerpt: "run eslint --fix on src/" });
  assert.equal(v.title, "Your prompt 12");
  assert.equal(v.sub, '"run eslint --fix on src/"');
  assert.equal(v.icon, "turn");
  const m = attachmentView({ type: "model", ref: "claude-opus-4-8", label: "claude-opus-4-8" });
  assert.equal(m.sub, "Compare models");
  const u = attachmentView({ type: "weird", ref: "abcdefghijklmnop" });
  assert.equal(u.icon, "other");
  assert.equal(u.title, "Item abcdefgh");
});

test("kindView maps the closed kind set and reads an unknown kind as a note", () => {
  assert.deepEqual(kindView("alert"), { label: "Alert", tone: "danger" });
  assert.deepEqual(kindView("coaching"), { label: "Coaching", tone: "accent" });
  assert.deepEqual(kindView("future_kind"), { label: "Note", tone: "neutral" });
});

test("offeredTopics follows the policy's topics in table order", () => {
  assert.deepEqual(offeredTopics(null).map((t) => t.id), ["budget", "model", "access", "guard", "other"]);
  const p = { dev_threads_allowed: true, topics: ["other", "budget", "x-new"], read_receipts_default: true, retention_days: 365 };
  assert.deepEqual(offeredTopics(p).map((t) => t.id), ["budget", "other", "x-new"]);
});

test("requestLinkFor offers the Requests flow only for the org's request topics", () => {
  const p = { dev_threads_allowed: true, request_topics: ["budget", "access"], read_receipts_default: true, retention_days: 365 };
  assert.equal(requestLinkFor("budget", p), "/requests?new=budget");
  assert.equal(requestLinkFor("access", p), "/requests?type=guard_exemption");
  assert.equal(requestLinkFor("model", p), null);
  assert.equal(requestLinkFor("budget", null), null);
  assert.equal(requestLinkFor("", p), null);
});

test("pageState puts the empty states before everything", () => {
  const rows: [Parameters<typeof pageState>[0], unknown, string][] = [
    [null, null, "loading"],
    [null, new Error("x"), "error"],
    [{ enrolled: false, rail: { state: "not_enrolled" } }, null, "not_enrolled"],
    [{ enrolled: true, rail: { state: "not_supported" } }, null, "not_supported"],
    [{ enrolled: true, rail: { state: "channel_off" } }, null, "channel_off"],
    [{ enrolled: true, rail: { state: "offline" } }, null, "ready"],
    [{ enrolled: true, rail: { state: "ok" } }, null, "ready"],
  ];
  for (const [d, e, want] of rows) assert.equal(pageState(d, e), want);
});

test("railBanner speaks only for offline and pending", () => {
  const fmt = () => "15:01";
  const off = railBanner({ state: "offline", last_ok_at: "2026-10-15T15:01:00Z" }, fmt);
  assert.equal(off?.tone, "warn");
  assert.match(off?.body ?? "", /Last contact 15:01/);
  assert.equal(railBanner({ state: "pending" }, fmt)?.tone, "info");
  assert.equal(railBanner({ state: "ok" }, fmt), null);
  assert.equal(railBanner(null, fmt), null);
});

test("listRows merges stored and pending threads newest first with pills", () => {
  const rows = listRows(
    [
      thread(),
      thread({ id: "t2", subject: "Access", started_by: "developer", last_author_kind: "developer", last_author_name: "Priya R", last_preview: "Thanks", last_at: "2026-09-28T10:00:00Z", unread: 0, needs_ack: 0, pending: 1 }),
    ],
    [outbox({ id: "c9", new_subject: "Higher budget?", new_topic: "budget", body: "please", state: "failed", created_at: "2026-10-15T15:00:00Z" })],
  );
  assert.deepEqual(rows.map((r) => r.key), ["pending:c9", "t1", "t2"]);
  assert.equal(rows[0]!.failed, true);
  assert.equal(rows[0]!.startedByYou, true);
  assert.equal(rows[1]!.unread, true);
  assert.equal(rows[1]!.needsAck, true);
  assert.equal(rows[1]!.preview, "Asha Kim: Hi Priya");
  assert.equal(rows[2]!.preview, "You: Thanks");
  assert.equal(rows[2]!.queued, true);
  assert.equal(rows[2]!.initials, "PR");
});

test("initials and listTime", () => {
  assert.equal(initials("Asha Kim"), "AK");
  assert.equal(initials("tom"), "T");
  assert.equal(initials(""), "?");
  const now = new Date(2026, 9, 15, 16, 0);
  assert.equal(listTime(new Date(2026, 9, 15, 14, 32).toISOString(), now), "14:32");
  assert.equal(listTime(new Date(2026, 9, 2, 9, 0).toISOString(), now), "Oct 2");
  assert.equal(listTime(new Date(2025, 0, 3).toISOString(), now), "Jan 3, 2025");
  assert.equal(listTime("nope", now), "");
});

test("pendingAck finds the newest unacknowledged ask from an admin", () => {
  assert.equal(pendingAck([msg()]), null);
  const ask = msg({ id: 2, require_ack: true });
  assert.equal(pendingAck([msg(), ask])?.id, 2);
  assert.equal(pendingAck([msg({ id: 3, require_ack: true, acked_at: "x" })]), null);
  assert.equal(pendingAck([msg({ author_kind: "developer", require_ack: true })]), null);
  assert.equal(ackPrompt({ author_name: "Asha Kim" }), "Asha asked you to acknowledge this message.");
  assert.equal(ackPrompt({ author_name: "" }), "Your admin asked you to acknowledge this message.");
});

test("unsentPosts drops receipts and posts that already arrived", () => {
  const list = unsentPosts(
    [outbox({ id: "a" }), outbox({ id: "b", kind: "receipt" }), outbox({ id: "c", state: "sent", result_message_id: 9 }), outbox({ id: "d", state: "sent" })],
    [msg({ id: 9, author_kind: "developer" }), msg({ id: 10, client_msg_id: "a" })],
  );
  assert.deepEqual(list.map((o) => o.id), ["d"]);
});

test("outboxView explains queued, sent and refused posts", () => {
  assert.equal(outboxView(outbox()).pill, "Queued");
  assert.equal(outboxView(outbox()).canRetry, false);
  assert.equal(outboxView(outbox({ attempts: 2 })).canRetry, true);
  assert.equal(outboxView(outbox({ state: "sent" })).pill, "Sent");
  const gone = outboxView(outbox({ state: "failed", last_error_code: "not_enrolled" }));
  assert.equal(gone.tone, "danger");
  assert.equal(gone.canRetry, false);
  assert.match(gone.note, /no longer enrolled/);
  const odd = outboxView(outbox({ state: "failed", last_error_code: "boom", last_error: "upstream 500" }));
  assert.equal(odd.canRetry, true);
  assert.match(odd.note, /upstream 500/);
});

test("readReceiptNote shows only when read receipts are on", () => {
  assert.equal(readReceiptNote(true), "Your admins can see when you have read this.");
  assert.equal(readReceiptNote(false), null);
});

test("sendErrorText maps every refusal code to a plain sentence", () => {
  assert.match(sendErrorText(409, '{"error":"not_enrolled","message":"x"}'), /not enrolled/);
  assert.match(sendErrorText(403, '{"error":"threads_disabled"}'), /start conversations/);
  assert.match(sendErrorText(403, '{"error":"topic_not_allowed"}'), /this topic/);
  assert.match(sendErrorText(429, '{"error":"outbox_full"}'), /Too many/);
  assert.equal(sendErrorText(400, '{"error":"invalid","message":"subject is longer than 200 bytes"}'), "Not sent: subject is longer than 200 bytes.");
  assert.match(sendErrorText(403, "forbidden: missing or mismatched confirm token"), /Reload/);
  assert.equal(sendErrorText(500, "oops"), "Not sent (HTTP 500).");
});

test("checkDraft validates replies and new conversations", () => {
  assert.deepEqual(checkDraft({ body: "  " }, false), { ok: false, reason: null });
  assert.equal(checkDraft({ body: "hi" }, false).ok, true);
  assert.equal(checkDraft({ body: "hi", subject: "s" }, true).reason, "Pick what this is about.");
  assert.equal(checkDraft({ body: "hi", topic: "budget" }, true).reason, "Add a subject.");
  assert.equal(checkDraft({ body: "", topic: "budget", subject: "s" }, true).reason, "Write your question.");
  assert.equal(checkDraft({ body: "x".repeat(8001) }, false).ok, false);
  assert.equal(checkDraft({ body: "hi", topic: "budget", subject: "s" }, true).ok, true);
});

test("isSendShortcut is Ctrl+Enter or Cmd+Enter only", () => {
  assert.equal(isSendShortcut({ key: "Enter", ctrlKey: true, metaKey: false }), true);
  assert.equal(isSendShortcut({ key: "Enter", ctrlKey: false, metaKey: true }), true);
  assert.equal(isSendShortcut({ key: "Enter", ctrlKey: false, metaKey: false }), false);
  assert.equal(isSendShortcut({ key: "a", ctrlKey: true, metaKey: false }), false);
});

test("requestInit carries JSON and the confirm token", () => {
  const init = requestInit({ a: 1 }, "tok");
  assert.equal(init.method, "POST");
  assert.deepEqual(init.headers, { "Content-Type": "application/json", "X-Observer-Confirm": "tok" });
  assert.equal(init.body, '{"a":1}');
});

test("attach options and addAttachment", () => {
  const s = sessionOptions([{ id: "s1", tool: "claude-code", project: "/home/dev/ledger-sync", started_at: "x" }], () => "today 10:12");
  assert.equal(s[0]!.title, "Session in ledger-sync");
  assert.deepEqual(s[0]!.attachment, { type: "session", ref: "s1", label: "Session in ledger-sync" });
  const p = projectOptions([{ id: 7, root_path: "C:\\work\\payments-api", session_count: 1 }]);
  assert.deepEqual(p[0]!.attachment, { type: "project", ref: "7", label: "payments-api" });
  assert.equal(p[0]!.sub, "1 session");
  const b = budgetAttachOptions([{ budget_id: "b1", scope: "member:u1", period: "calendar_month" }], () => "Your budget");
  assert.deepEqual(b[0]!.attachment, { type: "budget", ref: "b1", label: "Your budget" });
  assert.equal(b[0]!.sub, "Monthly cap");
  let list = addAttachment([], s[0]!.attachment);
  list = addAttachment(list, s[0]!.attachment);
  assert.equal(list.length, 1);
  let full: typeof list = [];
  for (let i = 0; i < MAX_ATTACHMENTS + 2; i++) full = addAttachment(full, { type: "session", ref: `s${i}` });
  assert.equal(full.length, MAX_ATTACHMENTS);
});

test("navBadge and showMessagesNav", () => {
  assert.equal(navBadge(null), "");
  assert.equal(navBadge(summary({ push: { unread: 1, newest: null } })), "1");
  assert.equal(navBadge(summary({ push: { unread: 12, newest: null } })), "9+");
  assert.equal(showMessagesNav(null), false);
  assert.equal(showMessagesNav(summary({ enrolled: false })), false);
  assert.equal(showMessagesNav(summary()), true);
});

test("decideToast: first poll records, a new message toasts once, surfaces gate it", () => {
  const rows: { name: string; prev: number; s: MessagesSummaryResponse | null; open: string | null; show: boolean; seen: number }[] = [
    { name: "no summary", prev: 5, s: null, open: null, show: false, seen: 5 },
    { name: "first poll records only", prev: -1, s: summary({ push: { unread: 1, newest: newest(7) } }), open: null, show: false, seen: 7 },
    { name: "first poll with nothing", prev: -1, s: summary(), open: null, show: false, seen: 0 },
    { name: "new message toasts", prev: 7, s: summary({ push: { unread: 1, newest: newest(8) } }), open: null, show: true, seen: 8 },
    { name: "same message again", prev: 8, s: summary({ push: { unread: 1, newest: newest(8) } }), open: null, show: false, seen: 8 },
    { name: "toast surface off", prev: 7, s: summary({ push: { unread: 1, newest: newest(8) }, surfaces: { ...surfaces, toast: false } }), open: null, show: false, seen: 8 },
    { name: "already reading the thread", prev: 7, s: summary({ push: { unread: 1, newest: newest(8, "t9") } }), open: "t9", show: false, seen: 8 },
    { name: "not enrolled", prev: 7, s: summary({ enrolled: false, push: { unread: 1, newest: newest(8) } }), open: null, show: false, seen: 7 },
  ];
  for (const r of rows) {
    const d = decideToast(r.prev, r.s, r.open);
    assert.equal(d.show, r.show, r.name);
    assert.equal(d.seen, r.seen, r.name);
  }
});

test("toast copy names the author and never a pronoun", () => {
  const m = newest(1);
  assert.equal(toastTitle(m), "Asha Kim: Opus for lint fixes");
  assert.equal(toastKicker(m), "New message from your admin, asks for acknowledgement");
  assert.equal(toastKicker({ ...m, kind: "alert" }), "Alert from your admin");
  assert.equal(threadLink("t 1"), "/messages?thread=t+1");
  assert.equal(threadLink("t1", true), "/messages?thread=t1&reply=1");
});

test("Settings card: one switch per [messages] key, defaults fill gaps", () => {
  assert.deepEqual(
    SURFACE_SETTINGS.map((s) => s.key).sort(),
    Object.keys(MESSAGES_CONFIG_DEFAULTS).sort(),
  );
  assert.deepEqual(messagesConfigFrom(null), MESSAGES_CONFIG_DEFAULTS);
  const v = messagesConfigFrom({ Messages: { Toast: false, Desktop: true, ReadReceipts: "yes" } });
  assert.equal(v.Toast, false);
  assert.equal(v.Desktop, true);
  assert.equal(v.ReadReceipts, true, "a non-boolean keeps the default");
  assert.equal(SETTINGS_MESSAGES_LINK, "/settings?section=org#messages-surfaces");
});

test("Settings card: read receipts are fixed on and explained on a managed enrolment", () => {
  const off = { ...MESSAGES_CONFIG_DEFAULTS, ReadReceipts: false };
  assert.deepEqual(surfaceSwitch("ReadReceipts", off, false, ""), { on: false, disabled: false, note: null });
  const locked = surfaceSwitch("ReadReceipts", off, true, "");
  assert.equal(locked.on, true);
  assert.equal(locked.disabled, true);
  assert.match(locked.note ?? "", /managed by your organization/);
  assert.match(surfaceSwitch("ReadReceipts", off, true, "Acme").note ?? "", /managed by Acme/);
  assert.deepEqual(surfaceSwitch("Toast", off, true, ""), { on: true, disabled: false, note: null });
  assert.equal(surfacesDirty(off, off), false);
  assert.equal(surfacesDirty(off, { ...off, Desktop: true }), true);
});
