// adminMessages - the pure half of the node dashboard's Messages page
// (admin and developer messaging, T-854; docs/plans/admin-developer-
// messaging-plan-2026-10-15.md sections 8 and 17.6).
//
// The wire shapes of the daemon's /api/messages routes
// (internal/intelligence/dashboard/messages.go) and every decision the page,
// the sidebar badge and the in-dashboard toast render: rail banners, list
// pills, attachment deep links, the "File this as a request" link, the
// composer's send errors, and whether a newly arrived message deserves a
// toast. No React, no fetch, no router: pinned by adminMessages.test.ts under
// `node --test`.
//
// Copy rule (D-688 ruling 6): never infer a pronoun from a name. Copy uses
// the person's name or "they".

import { DRAWER_MESSAGE_PARAM, DRAWER_TAB_PARAM } from "./drawerTab.ts";

// ---------- wire shapes ----------

/** Rail states the daemon reports (a closed set). */
export type RailState = "not_enrolled" | "pending" | "ok" | "offline" | "not_supported" | "channel_off";

/** MessagesRail mirrors messagesRailView. */
export interface MessagesRail {
  state: RailState;
  fetch_state?: string;
  last_ok_at?: string;
  last_attempt_at?: string;
  last_error?: string;
}

/** MessagesPolicy mirrors orgcontract.OrgMessageNodePolicy. */
export interface MessagesPolicy {
  dev_threads_allowed: boolean;
  topics?: string[];
  request_topics?: string[];
  read_receipts_default: boolean;
  retention_days: number;
}

/** MessagesSurfaces mirrors messagesSurfaces (the developer's [messages]). */
export interface MessagesSurfaces {
  toast: boolean;
  vscode: boolean;
  statusline: boolean;
  desktop: boolean;
  alerts_only: boolean;
  read_receipts: boolean;
  /** The enrolment is organization-managed: read receipts are always sent
   *  whatever read_receipts says (absent on an older daemon = false). */
  read_receipts_locked?: boolean;
}

/** MessageAttachment mirrors orgcontract.OrgMessageAttachment. */
export interface MessageAttachment {
  type: string;
  ref: string;
  label?: string;
  excerpt?: string;
}

/** ThreadSummary mirrors store.OrgMessageThreadSummary. */
export interface ThreadSummary {
  id: string;
  subject: string;
  kind: string;
  topic?: string;
  started_by: string;
  status: string;
  updated_at: string;
  last_author_kind?: string;
  last_author_name?: string;
  last_preview?: string;
  last_at?: string;
  messages: number;
  unread: number;
  needs_ack: number;
  pending: number;
  failed: number;
}

/** OutboxItem mirrors store.OrgMessageOutboxItem (id is the client id). */
export interface OutboxItem {
  id: string;
  kind: string;
  thread_id?: string;
  new_subject?: string;
  new_topic?: string;
  body?: string;
  attachments: MessageAttachment[] | null;
  receipt_message_id?: number;
  receipt_state?: string;
  receipt_at?: string;
  created_at: string;
  state: "queued" | "sent" | "failed" | string;
  attempts: number;
  last_error?: string;
  last_error_code?: string;
  last_attempt_at?: string;
  sent_at?: string;
  result_message_id?: number;
  result_thread_id?: string;
}

/** InboxMessage mirrors store.OrgInboxMessage. */
export interface InboxMessage {
  id: number;
  thread_id: string;
  author_kind: string;
  author_name: string;
  body: string;
  require_ack: boolean;
  created_at: string;
  client_msg_id?: string;
  attachments: MessageAttachment[] | null;
  received_at: string;
  read_at?: string;
  acked_at?: string;
}

/** MessagesSummary mirrors store.OrgMessageSummary. */
export interface MessagesSummaryCounts {
  unread: number;
  unread_threads: number;
  needs_ack: number;
  unread_alerts: number;
  failed_outbox: number;
  newest: NewestMessage | null;
  newest_alert: NewestMessage | null;
}

/** NewestMessage mirrors store.OrgMessageNewest. */
export interface NewestMessage {
  thread_id: string;
  message_id: number;
  subject: string;
  author_name: string;
  kind: string;
  created_at: string;
  require_ack: boolean;
}

/** MessagesPageResponse mirrors GET /api/messages. */
export interface MessagesPageResponse {
  enrolled: boolean;
  org_name?: string;
  rail: MessagesRail;
  policy: MessagesPolicy | null;
  ask_allowed: boolean;
  read_receipts: boolean;
  surfaces: MessagesSurfaces;
  threads: ThreadSummary[];
  pending_threads: OutboxItem[];
  summary: MessagesSummaryCounts;
  generated_at: string;
  confirm_token: string;
}

/** ThreadResponse mirrors GET /api/messages/threads/{id}. */
export interface ThreadResponse {
  thread: ThreadSummary;
  messages: InboxMessage[];
  outbox: OutboxItem[];
  read_receipts: boolean;
  rail: MessagesRail;
  confirm_token: string;
}

/** MessagesSummaryResponse mirrors GET /api/messages/summary. */
export interface MessagesSummaryResponse extends MessagesSummaryCounts {
  enrolled: boolean;
  rail: MessagesRail;
  push: { unread: number; newest: NewestMessage | null };
  surfaces: MessagesSurfaces;
}

/** SendBody is POST /api/messages. */
export interface SendBody {
  client_msg_id: string;
  thread_id?: string;
  subject?: string;
  topic?: string;
  body: string;
  attachments?: MessageAttachment[];
}

// ---------- limits (orgcontract.OrgMessageMax*) ----------

export const MAX_BODY = 8000;
export const MAX_SUBJECT = 200;
export const MAX_ATTACHMENTS = 8;

// ---------- kinds and topics ----------

/** A message kind as the page shows it. An unknown kind reads as a note. */
export interface KindView {
  label: string;
  tone: "neutral" | "accent" | "danger";
}

const KINDS: Record<string, KindView> = {
  note: { label: "Note", tone: "neutral" },
  coaching: { label: "Coaching", tone: "accent" },
  alert: { label: "Alert", tone: "danger" },
};

/** kindView: the pill for a message kind (internal/orgmsg's closed set). */
export function kindView(kind: string): KindView {
  return KINDS[kind] ?? KINDS.note!;
}

/** The topic table, in the order the "Ask my admin" form offers them
 *  (internal/orgmsg topics). An unknown topic is shown by its id. */
export const TOPICS: readonly { id: string; label: string }[] = [
  { id: "budget", label: "Budget" },
  { id: "model", label: "Models" },
  { id: "access", label: "Access" },
  { id: "guard", label: "Guardrails" },
  { id: "other", label: "Something else" },
];

export function topicLabel(id: string): string {
  return TOPICS.find((t) => t.id === id)?.label ?? id;
}

/**
 * offeredTopics is the topic picker: the policy's topics in the table's
 * order (an id the table does not know is kept, after the known ones), or
 * the whole table when no policy has arrived yet (the org re-checks on send).
 */
export function offeredTopics(policy: MessagesPolicy | null | undefined): { id: string; label: string }[] {
  const allowed = policy?.topics;
  if (!allowed || allowed.length === 0) return TOPICS.map((t) => ({ ...t }));
  const known = TOPICS.filter((t) => allowed.includes(t.id)).map((t) => ({ ...t }));
  const extra = allowed.filter((id) => !TOPICS.some((t) => t.id === id)).map((id) => ({ id, label: id }));
  return [...known, ...extra];
}

/**
 * The Requests page entry each request topic opens (lib/requestEntry.ts):
 * a budget question opens a budget-increase draft, an access or guardrail
 * question a guard exemption draft. A topic not listed opens the page.
 */
const REQUEST_ENTRY: Record<string, string> = {
  budget: "/requests?new=budget",
  access: "/requests?type=guard_exemption",
  guard: "/requests?type=guard_exemption",
};

/**
 * requestLinkFor is the "File this as a request instead" link for a topic,
 * or null when the org does not offer that topic as a request.
 */
export function requestLinkFor(topic: string, policy: MessagesPolicy | null | undefined): string | null {
  if (!topic || !policy?.request_topics?.includes(topic)) return null;
  return REQUEST_ENTRY[topic] ?? "/requests";
}

// ---------- rail ----------

/** RailView is what the page says about the delivery rail, or null. */
export interface RailView {
  tone: "info" | "warn" | "danger";
  title: string;
  body: string;
}

/**
 * railBanner is the banner above the conversation for an enrolled node whose
 * rail is not healthy. The three empty states (not enrolled, not supported,
 * channel off) are full-page states, not banners: see pageState.
 */
export function railBanner(rail: MessagesRail | null | undefined, lastContact: (iso: string) => string): RailView | null {
  if (!rail) return null;
  if (rail.state === "offline") {
    const when = rail.last_ok_at ? ` Last contact ${lastContact(rail.last_ok_at)}.` : "";
    return {
      tone: "warn",
      title: "Can't reach the org server.",
      body: `${when} New messages arrive and replies send once it is reachable again; Observer keeps trying every sync.`.trim(),
    };
  }
  if (rail.state === "pending") {
    return {
      tone: "info",
      title: "Waiting for the first sync.",
      body: "Messages from your organization show up here after this machine's next sync with the org server.",
    };
  }
  return null;
}

/** The page's top-level state (empty states win over everything). */
export type PageState = "loading" | "error" | "not_enrolled" | "not_supported" | "channel_off" | "ready";

export function pageState(data: Pick<MessagesPageResponse, "enrolled" | "rail"> | null | undefined, error: unknown): PageState {
  if (!data) return error ? "error" : "loading";
  if (!data.enrolled || data.rail.state === "not_enrolled") return "not_enrolled";
  if (data.rail.state === "not_supported") return "not_supported";
  if (data.rail.state === "channel_off") return "channel_off";
  return "ready";
}

// ---------- thread list ----------

/** ListRow is one row of the thread list: a stored thread or a
 *  developer-started conversation the org has not stored yet. */
export interface ListRow {
  /** Thread id, or "pending:<client id>" for an unstored conversation. */
  key: string;
  threadId: string | null;
  outboxId: string | null;
  subject: string;
  preview: string;
  at: string;
  unread: boolean;
  kind: string;
  topic?: string;
  needsAck: boolean;
  startedByYou: boolean;
  queued: boolean;
  failed: boolean;
  closed: boolean;
  initials: string;
}

/** initials: up to two letters for an avatar ("Asha Kim" -> "AK"). */
export function initials(name: string | null | undefined): string {
  const parts = (name ?? "").trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  const first = parts[0]![0] ?? "";
  const last = parts.length > 1 ? (parts[parts.length - 1]![0] ?? "") : "";
  return (first + last).toUpperCase();
}

function previewOf(t: ThreadSummary): string {
  const p = (t.last_preview ?? "").trim();
  if (!p) return "";
  if (t.last_author_kind === "developer") return `You: ${p}`;
  return t.last_author_name ? `${t.last_author_name}: ${p}` : p;
}

/**
 * listRows merges the stored threads and the pending (not yet stored)
 * developer-started conversations into one list, newest first. The list
 * marks what needs attention (unread, an ask to acknowledge, a post that
 * has not reached the org); everything else is in the thread view.
 */
export function listRows(threads: readonly ThreadSummary[], pending: readonly OutboxItem[]): ListRow[] {
  const rows: ListRow[] = threads.map((t) => {
    return {
      key: t.id,
      threadId: t.id,
      outboxId: null,
      subject: t.subject || "(no subject)",
      preview: previewOf(t),
      at: t.last_at || t.updated_at,
      unread: t.unread > 0,
      kind: t.kind,
      topic: t.topic,
      needsAck: t.needs_ack > 0,
      startedByYou: t.started_by === "developer",
      queued: t.pending > 0 && t.failed === 0,
      failed: t.failed > 0,
      closed: t.status === "closed",
      initials: initials(t.last_author_name || (t.started_by === "developer" ? "You" : "Admin")),
    };
  });
  for (const p of pending) {
    rows.push({
      key: `pending:${p.id}`,
      threadId: null,
      outboxId: p.id,
      subject: p.new_subject || "(no subject)",
      preview: p.body ? `You: ${p.body}` : "",
      at: p.created_at,
      unread: false,
      kind: "note",
      topic: p.new_topic,
      needsAck: false,
      startedByYou: true,
      queued: p.state !== "failed",
      failed: p.state === "failed",
      closed: false,
      initials: "Y",
    });
  }
  rows.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : a.key < b.key ? -1 : 1));
  return rows;
}

/**
 * listTime is the compact time on a list row: the clock for today, else
 * the short date ("Oct 2"), else the year when not this year.
 */
export function listTime(iso: string, now: Date = new Date()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  if (sameDay) {
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }
  const month = d.toLocaleString("en-US", { month: "short" });
  if (d.getFullYear() === now.getFullYear()) return `${month} ${d.getDate()}`;
  return `${month} ${d.getDate()}, ${d.getFullYear()}`;
}

// ---------- thread view ----------

/** The newest admin message in a thread that still waits for an ack. */
export function pendingAck(messages: readonly InboxMessage[]): InboxMessage | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (m.author_kind === "admin" && m.require_ack && !m.acked_at) return m;
  }
  return null;
}

/** firstName: the first word of a name, for copy like "Asha asked you". */
export function firstName(name: string | null | undefined): string {
  const n = (name ?? "").trim().split(/\s+/)[0] ?? "";
  return n || "Your admin";
}

/** ackPrompt is the Acknowledge bar's sentence. */
export function ackPrompt(m: Pick<InboxMessage, "author_name">): string {
  return `${firstName(m.author_name)} asked you to acknowledge this message.`;
}

/**
 * The outbox items a thread view shows inline under the conversation: the
 * developer's own posts the org has not stored yet. A sent post whose
 * message already arrived in the pull is dropped (it is in `messages`).
 */
export function unsentPosts(outbox: readonly OutboxItem[] | null | undefined, messages: readonly InboxMessage[]): OutboxItem[] {
  const have = new Set(messages.map((m) => m.client_msg_id).filter(Boolean));
  return (outbox ?? []).filter((o) => o.kind !== "receipt" && !have.has(o.id) && !(o.state === "sent" && o.result_message_id != null && messages.some((m) => m.id === o.result_message_id)));
}

/** OutboxView is how one waiting post reads. */
export interface OutboxView {
  tone: "warn" | "danger" | "info";
  pill: string;
  note: string;
  canRetry: boolean;
}

const OUTBOX_ERRORS: Record<string, string> = {
  not_enrolled: "This machine is no longer enrolled with an organization. Your text was kept here so you can copy it.",
  not_supported: "Your organization's server does not take messages yet. Your text was kept here so you can copy it.",
  threads_disabled: "Your organization does not let you start conversations. Your text was kept here so you can copy it.",
  topic_not_allowed: "Your organization does not take messages on this topic. Your text was kept here so you can copy it.",
  thread_closed: "An admin closed this conversation. Your text was kept here so you can copy it.",
  not_found: "Your organization no longer has this conversation. Your text was kept here so you can copy it.",
  invalid: "The org server refused this message as invalid. Your text was kept here so you can copy it.",
};

/** outboxView: the pill and note for a waiting post. */
export function outboxView(item: OutboxItem): OutboxView {
  if (item.state === "failed") {
    const code = item.last_error_code ?? "";
    return {
      tone: "danger",
      pill: "Not sent",
      note: OUTBOX_ERRORS[code] ?? (item.last_error ? `The org server refused it: ${item.last_error}` : "The org server refused it. Your text was kept here so you can copy it."),
      canRetry: !(code in OUTBOX_ERRORS) || code === "invalid",
    };
  }
  if (item.state === "sent") {
    return { tone: "info", pill: "Sent", note: "Delivered to the org server. It shows in the conversation after the next sync.", canRetry: false };
  }
  return {
    tone: "warn",
    pill: "Queued",
    note: "Saved on this machine. Sends when the org server is reachable.",
    canRetry: item.attempts > 0,
  };
}

/** readReceiptNote is the footer line under a thread, or null when off. */
export function readReceiptNote(readReceipts: boolean): string | null {
  return readReceipts ? "Your admins can see when you have read this." : null;
}

// ---------- send ----------

/** The send error codes POST /api/messages answers with. */
const SEND_ERRORS: Record<string, string> = {
  not_enrolled: "Messages go to an organization, and this machine is not enrolled.",
  not_supported: "Your organization's server does not support messages yet.",
  threads_disabled: "Your organization does not let you start conversations.",
  topic_not_allowed: "Your organization does not take messages on this topic.",
  outbox_full: "Too many messages are waiting to be sent. Discard one, or wait until the org server is reachable.",
  bad_request: "The dashboard sent a malformed message. Reload the page and try again.",
};

/**
 * sendErrorText turns a refused send's {error, message} body into one plain
 * sentence. `invalid` carries the server's own reason (a too-long subject,
 * an attachment over the limit).
 */
export function sendErrorText(status: number, body: string): string {
  let parsed: { error?: string; message?: string } | null = null;
  try {
    parsed = JSON.parse(body) as { error?: string; message?: string };
  } catch {
    parsed = null;
  }
  const code = parsed?.error ?? "";
  if (code === "invalid" && parsed?.message) return `Not sent: ${parsed.message}.`;
  if (code && SEND_ERRORS[code]) return SEND_ERRORS[code]!;
  if (status === 403) return "The dashboard's confirm token expired. Reload the page and try again.";
  return parsed?.message ? `Not sent: ${parsed.message}` : `Not sent (HTTP ${status}).`;
}

/** DraftCheck is whether a draft may be sent, and why not. */
export interface DraftCheck {
  ok: boolean;
  reason: string | null;
}

/** checkDraft validates a reply or a new conversation before sending. */
export function checkDraft(d: { body: string; subject?: string; topic?: string; attachments?: readonly unknown[] }, isNew: boolean): DraftCheck {
  const body = d.body.trim();
  if (isNew) {
    if (!d.topic) return { ok: false, reason: "Pick what this is about." };
    const subject = (d.subject ?? "").trim();
    if (!subject) return { ok: false, reason: "Add a subject." };
    if (subject.length > MAX_SUBJECT) return { ok: false, reason: `Keep the subject under ${MAX_SUBJECT} characters.` };
  }
  if (!body) return { ok: false, reason: isNew ? "Write your question." : null };
  if (body.length > MAX_BODY) return { ok: false, reason: `Keep the message under ${MAX_BODY} characters.` };
  if ((d.attachments?.length ?? 0) > MAX_ATTACHMENTS) return { ok: false, reason: `At most ${MAX_ATTACHMENTS} attachments.` };
  return { ok: true, reason: null };
}

/** isSendShortcut: Ctrl+Enter (Cmd+Enter on a Mac) sends the composer. */
export function isSendShortcut(e: { key: string; ctrlKey: boolean; metaKey: boolean }): boolean {
  return e.key === "Enter" && (e.ctrlKey || e.metaKey);
}

/** newClientMsgId mints the idempotency key a send carries. */
export function newClientMsgId(rand: () => string = defaultRand): string {
  return rand();
}

function defaultRand(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return `m-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** requestInit is a JSON POST carrying the owner-local confirm token. */
export function requestInit(body: unknown, confirmToken: string): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Observer-Confirm": confirmToken },
    body: JSON.stringify(body ?? {}),
  };
}

// ---------- attachments ----------

/** AttachmentView is one attachment card: its label, its sub line and the
 *  node page it opens. */
export interface AttachmentView {
  title: string;
  sub: string;
  to: string;
  icon: "session" | "turn" | "model" | "guard_event" | "project" | "budget" | "request" | "other";
}

const TYPE_TITLE: Record<string, string> = {
  session: "Session",
  turn: "Turn",
  model: "Model",
  guard_event: "Guard event",
  project: "Project",
  budget: "Budget",
  request: "Request",
};

/** The query param on /sessions that scrolls to and highlights one
 *  message of the open session (SessionDetailPanel). */
export const SESSION_MESSAGE_PARAM = DRAWER_MESSAGE_PARAM;

/** sessionLink opens the node's own session detail, optionally on one
 *  message (the Messages tab's row key, sessionmsg's message id). */
export function sessionLink(sessionId: string, messageKey?: string): string {
  const q = new URLSearchParams({ session: sessionId });
  if (messageKey) {
    q.set(DRAWER_TAB_PARAM, "messages");
    q.set(SESSION_MESSAGE_PARAM, messageKey);
  }
  return `/sessions?${q.toString()}`;
}

/**
 * attachmentLink is the node page an attachment opens: an org message points
 * at the developer's OWN copy of the object on this machine.
 */
export function attachmentLink(a: Pick<MessageAttachment, "type" | "ref">): string {
  const ref = a.ref ?? "";
  switch (a.type) {
    case "session":
      return sessionLink(ref);
    case "turn": {
      const i = ref.indexOf("#");
      if (i <= 0) return sessionLink(ref);
      return sessionLink(ref.slice(0, i), ref.slice(i + 1));
    }
    case "model":
      return "/cost?tab=by-model";
    case "guard_event":
      return "/security?tab=verdicts";
    case "project":
      return /^\d+$/.test(ref) ? `/projects?project=${ref}` : `/projects?root=${encodeURIComponent(ref)}`;
    case "budget":
      return "/cost?tab=budgets";
    case "request":
      return "/requests";
    default:
      return "/messages";
  }
}

const SUB: Record<string, string> = {
  session: "Open your session",
  turn: "Open this message in your session",
  model: "Compare models",
  guard_event: "Open in Security",
  project: "Open the project",
  budget: "Open your budgets",
  request: "Open Requests",
};

/** attachmentView builds a card for one attachment. */
export function attachmentView(a: MessageAttachment): AttachmentView {
  const known = a.type in TYPE_TITLE;
  const title = a.label?.trim() || (a.type === "turn" ? `${TYPE_TITLE.turn} in ${shortRef(a.ref.split("#")[0] ?? "")}` : `${TYPE_TITLE[a.type] ?? "Item"} ${shortRef(a.ref)}`);
  const sub = a.excerpt?.trim() ? `"${truncate(a.excerpt.trim(), 60)}"` : (SUB[a.type] ?? "Open");
  return { title, sub, to: attachmentLink(a), icon: known ? (a.type as AttachmentView["icon"]) : "other" };
}

function shortRef(ref: string): string {
  return ref.length > 12 ? ref.slice(0, 8) : ref;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 3).trimEnd()}...` : s;
}

// ---------- attach picker ----------

/** AttachOption is one thing on this machine the developer may attach. */
export interface AttachOption {
  key: string;
  attachment: MessageAttachment;
  title: string;
  sub: string;
}

/** sessionOptions: recent sessions as attachments (the ref is the id). */
export function sessionOptions(rows: readonly { id: string; tool: string; project: string; started_at: string }[], fmtWhen: (iso: string) => string): AttachOption[] {
  return rows.map((r) => {
    const project = baseName(r.project);
    return {
      key: `session:${r.id}`,
      attachment: { type: "session", ref: r.id, label: clip(`Session in ${project || "unknown project"}`, 120) },
      title: `Session in ${project || "unknown project"}`,
      sub: `${r.tool} · ${fmtWhen(r.started_at)}`,
    };
  });
}

/** projectOptions: the projects this machine knows (the ref is the id). */
export function projectOptions(rows: readonly { id: number; root_path: string; session_count: number }[]): AttachOption[] {
  return rows.map((r) => {
    const name = baseName(r.root_path) || r.root_path;
    return {
      key: `project:${r.id}`,
      attachment: { type: "project", ref: String(r.id), label: clip(name, 120) },
      title: name,
      sub: `${r.session_count} session${r.session_count === 1 ? "" : "s"}`,
    };
  });
}

/** budgetOptions: the org budgets the node's budget rail names. */
export function budgetAttachOptions(rows: readonly { budget_id: string; scope: string; period: string }[], scopeWords: (scope: string) => string): AttachOption[] {
  return rows.map((b) => ({
    key: `budget:${b.budget_id}`,
    attachment: { type: "budget", ref: b.budget_id, label: clip(scopeWords(b.scope), 120) },
    title: scopeWords(b.scope),
    sub: periodWords(b.period),
  }));
}

function periodWords(p: string): string {
  return p === "calendar_month" ? "Monthly cap" : p === "calendar_day" ? "Daily cap" : p === "rolling_30d" ? "Rolling 30 day cap" : "Budget";
}

function baseName(p: string): string {
  const parts = (p ?? "").split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? "";
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) : s;
}

/** addAttachment appends unless it is already there or the list is full. */
export function addAttachment(list: readonly MessageAttachment[], a: MessageAttachment): MessageAttachment[] {
  if (list.length >= MAX_ATTACHMENTS) return [...list];
  if (list.some((x) => x.type === a.type && x.ref === a.ref)) return [...list];
  return [...list, a];
}

// ---------- push surfaces ----------

/** navBadge is the sidebar count: the push view's unread (alerts_only
 *  already applied server-side), "" at zero, "9+" past nine. */
export function navBadge(s: Pick<MessagesSummaryResponse, "push"> | null | undefined): string {
  const n = s?.push?.unread ?? 0;
  if (!Number.isFinite(n) || n <= 0) return "";
  return n > 9 ? "9+" : String(Math.floor(n));
}

/** showMessagesNav: the nav item shows only on an enrolled node (D-695). */
export function showMessagesNav(s: Pick<MessagesSummaryResponse, "enrolled"> | null | undefined): boolean {
  return s?.enrolled === true;
}

/** ToastDecision is whether to raise the in-dashboard toast. */
export interface ToastDecision {
  show: boolean;
  /** The message id to remember as seen (the newest push message, or the
   *  previous value when there is none). */
  seen: number;
  message: NewestMessage | null;
}

/**
 * decideToast raises the toast once per newly arrived push message.
 *
 *  - The first poll of a page load only RECORDS the newest id (seen = -1
 *    means "nothing recorded yet"), so reloading the dashboard never
 *    re-announces a message the developer has already been told about.
 *  - Off when the developer turned the toast surface off.
 *  - Never for a message in the thread the developer is already reading.
 */
export function decideToast(prevSeen: number, s: MessagesSummaryResponse | null | undefined, openThreadId: string | null): ToastDecision {
  const newest = s?.push?.newest ?? null;
  const id = newest?.message_id ?? 0;
  if (!s || !s.enrolled) return { show: false, seen: prevSeen, message: null };
  if (prevSeen < 0) return { show: false, seen: id, message: null };
  if (!newest || id <= prevSeen) return { show: false, seen: Math.max(prevSeen, id), message: null };
  if (!s.surfaces?.toast) return { show: false, seen: id, message: null };
  if (openThreadId && newest.thread_id === openThreadId) return { show: false, seen: id, message: null };
  return { show: true, seen: id, message: newest };
}

/** toastTitle is the toast's headline for a newly arrived message. */
export function toastTitle(m: NewestMessage): string {
  return `${m.author_name || "Your admin"}: ${m.subject || "New message"}`;
}

/** toastKicker is the small line above the toast headline. */
export function toastKicker(m: NewestMessage): string {
  if (m.kind === "alert") return "Alert from your admin";
  return m.require_ack ? "New message from your admin, asks for acknowledgement" : "New message from your admin";
}

/** threadLink opens one conversation on the Messages page. */
export function threadLink(threadId: string, reply = false): string {
  const q = new URLSearchParams({ thread: threadId });
  if (reply) q.set("reply", "1");
  return `/messages?${q.toString()}`;
}

// ---------- Settings: where messages show up ----------

/** MessagesConfigValues is the [messages] section as GET /api/config serves
 *  it (Go field names) and PUT /api/config/section/messages accepts. */
export interface MessagesConfigValues {
  Toast: boolean;
  VSCode: boolean;
  Statusline: boolean;
  Desktop: boolean;
  AlertsOnly: boolean;
  ReadReceipts: boolean;
}

/** The [messages] defaults (config.DefaultMessagesConfig). */
export const MESSAGES_CONFIG_DEFAULTS: MessagesConfigValues = {
  Toast: true,
  VSCode: true,
  Statusline: true,
  Desktop: false,
  AlertsOnly: false,
  ReadReceipts: true,
};

/** One switch on the Settings card, in display order. */
export interface SurfaceSetting {
  key: keyof MessagesConfigValues;
  label: string;
  help: string;
}

/** SURFACE_SETTINGS is the card's table: one row per [messages] key. */
export const SURFACE_SETTINGS: readonly SurfaceSetting[] = [
  { key: "Toast", label: "Toast while the dashboard is open", help: "A small notice with Open and Reply when a message arrives while this dashboard is open." },
  { key: "VSCode", label: "VS Code notification", help: "A notification in VS Code, and an \"N from admin\" item in its status bar while anything is unread." },
  { key: "Statusline", label: "Status line hint", help: "\"1 message from your admin\" in the Observer status line of your AI tool. It never shows message text." },
  { key: "Desktop", label: "Desktop notification", help: "An operating-system notification with the sender and subject only. Off until you turn it on." },
  { key: "AlertsOnly", label: "Alerts only", help: "Limit every surface above, and the bell, to messages an admin marked as an alert. This page still lists everything." },
  { key: "ReadReceipts", label: "Read receipts", help: "Let your admins see when you have read a message. Acknowledging a message is always reported, because it is something you choose to do." },
];

/** SETTINGS_MESSAGES_LINK opens the Settings card (the "Org sharing" section). */
export const SETTINGS_MESSAGES_LINK = "/settings?section=org#messages-surfaces";

/** messagesConfigFrom reads [messages] out of a GET /api/config payload,
 *  falling back to the defaults key by key. */
export function messagesConfigFrom(config: unknown): MessagesConfigValues {
  const raw = (config as { Messages?: Partial<MessagesConfigValues> } | null | undefined)?.Messages ?? {};
  const out = { ...MESSAGES_CONFIG_DEFAULTS };
  for (const k of Object.keys(out) as (keyof MessagesConfigValues)[]) {
    if (typeof raw[k] === "boolean") out[k] = raw[k] as boolean;
  }
  return out;
}

/** SwitchView is how one switch renders. */
export interface SwitchView {
  on: boolean;
  disabled: boolean;
  note: string | null;
}

/**
 * surfaceSwitch renders one switch. Read receipts on a managed enrolment are
 * fixed on: the org client sends them whatever the file says, so the card
 * shows the switch on, disabled, and says why, never a choice that does
 * nothing.
 */
export function surfaceSwitch(key: keyof MessagesConfigValues, values: MessagesConfigValues, locked: boolean, orgName: string): SwitchView {
  if (key === "ReadReceipts" && locked) {
    return {
      on: true,
      disabled: true,
      note: `Always on: this machine is managed by ${orgName || "your organization"}, which receives read receipts on every managed machine.`,
    };
  }
  return { on: values[key], disabled: false, note: null };
}

/** surfacesDirty reports whether the draft differs from what is saved. */
export function surfacesDirty(saved: MessagesConfigValues, draft: MessagesConfigValues): boolean {
  return (Object.keys(saved) as (keyof MessagesConfigValues)[]).some((k) => saved[k] !== draft[k]);
}
