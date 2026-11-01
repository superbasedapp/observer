import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import clsx from "clsx";
import {
  ArrowLeft,
  Check,
  Clock,
  Cpu,
  FolderOpen,
  Hand,
  History,
  Inbox,
  Lock,
  MessagesSquare,
  Paperclip,
  Plus,
  Send,
  ShieldAlert,
  SquareTerminal,
  Unplug,
  Wallet,
  WifiOff,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  Button,
  Callout,
  EmptyState,
  ErrorState,
  Icon,
  Input,
  Modal,
  PageHeader,
  Pill,
  SegmentedControl,
  Skeleton,
  Textarea,
  Tooltip,
} from "@/components/primitives";
import { navIcon } from "@/lib/nav";
import { ApiError, fetchJSON } from "@/lib/api";
import { apiCache, useApi } from "@/lib/useApi";
import { fmtClock, fmtDateTime, fmtRelative } from "@/lib/format";
import { writeClipboard } from "@/lib/clipboard";
import { scopeWords, type RequestableBudget } from "@/lib/requestBudgets";
import type { ProjectsResponse, SessionsResponse } from "@/lib/types";
import { MESSAGES_SUMMARY_PATH } from "@/lib/useMessagesSummary";
import {
  ackPrompt,
  addAttachment,
  attachmentView,
  budgetAttachOptions,
  checkDraft,
  initials,
  isSendShortcut,
  kindView,
  listRows,
  listTime,
  newClientMsgId,
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
  sessionOptions,
  SETTINGS_MESSAGES_LINK,
  topicLabel,
  unsentPosts,
  type AttachOption,
  type AttachmentView,
  type InboxMessage,
  type ListRow,
  type MessageAttachment,
  type MessagesPageResponse,
  type MessagesSurfaces,
  type OutboxItem,
  type ThreadResponse,
} from "@/lib/adminMessages";

// Messages - the developer's side of admin and developer messaging (T-854,
// docs/plans/admin-developer-messaging-plan-2026-10-15.md). A master-detail
// page: the conversation list on the left, one conversation (or the "Ask my
// admin" form) on the right; at phone width the list and the conversation
// take turns, with a Back button.
//
// Everything is read from the daemon's node-local tables (GET /api/messages
// and /api/messages/threads/{id}); only the writes reach the org, through the
// daemon's outbox. Every write echoes the owner-local confirm token, like the
// notification bell. The pure decisions (list pills, deep links, rail
// banners, send errors) live in lib/adminMessages.ts.
//
// URL state: ?thread=<id> opens a conversation, ?pending=<client id> one the
// org has not stored yet, ?compose=1 the "Ask my admin" form, ?reply=1
// focuses the reply box (the toast's Reply).

const PAGE_PATH = "/api/messages";
const POLL_MS = 30_000;
const COMPOSER_ID = "messages-composer";

type StatusFilter = "all" | "open" | "closed";

/** refreshAfterWrite re-reads every surface a messaging write moves: the
 *  page, the open conversation, the summary (nav badge, toast) and the bell. */
function refreshAfterWrite(reloads: (() => void)[]) {
  apiCache.invalidate(MESSAGES_SUMMARY_PATH);
  apiCache.invalidate("/api/notifications");
  for (const r of reloads) r();
}

async function postJSON<T>(path: string, body: unknown, token: string): Promise<T | null> {
  try {
    return await fetchJSON<T>(path, undefined, requestInit(body, token));
  } catch (e) {
    // A 204 (discard) has no body to parse; that is success.
    if (e instanceof SyntaxError) return null;
    throw e;
  }
}

function errorText(e: unknown): string {
  if (e instanceof ApiError) return sendErrorText(e.status, e.body);
  return e instanceof Error ? e.message : String(e);
}

const ATTACH_ICON: Record<AttachmentView["icon"], LucideIcon> = {
  session: History,
  turn: SquareTerminal,
  model: Cpu,
  guard_event: ShieldAlert,
  project: FolderOpen,
  budget: Wallet,
  request: Inbox,
  other: Paperclip,
};

export function MessagesPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<StatusFilter>("all");
  const page = useApi<MessagesPageResponse>(PAGE_PATH, { status }, [status], { refreshMs: POLL_MS });
  const data = page.data;
  const state = pageState(data, page.error);

  const threadId = params.get("thread");
  const pendingId = params.get("pending");
  const composing = params.get("compose") === "1";
  const replyFocus = params.get("reply") === "1";
  const selected = threadId ? threadId : pendingId ? `pending:${pendingId}` : composing ? "compose" : null;

  const select = useCallback(
    (next: Record<string, string> | null) => {
      setParams(() => new URLSearchParams(next ?? {}), { replace: false });
    },
    [setParams],
  );

  const rows = useMemo(() => listRows(data?.threads ?? [], data?.pending_threads ?? []), [data]);
  const orgName = data?.org_name || "your organization";

  if (state === "loading") return <PageSkeleton />;
  if (state === "error") {
    return (
      <div className="p-4 sm:p-6">
        <ErrorState variant="page" title="Messages could not load" error={page.error} onRetry={page.reload} />
      </div>
    );
  }
  if (state !== "ready") return <NotReady state={state} orgName={orgName} />;

  const banner = railBanner(data!.rail, (iso) => fmtRelative(iso));

  return (
    // Fills the page box from the top bar down. The shell takes the
    // floating terminal dock's clearance off that box (T-855), so the
    // composer and Send sit just above the dock and no empty band is left.
    <div className="flex min-h-full flex-col lg:flex-row">
      {/* The list. Hidden at phone width while a conversation is open. */}
      <aside
        className={clsx(
          "flex w-full shrink-0 flex-col border-line-1 bg-bg-1 lg:w-[340px] lg:border-b lg:border-r",
          selected && "hidden lg:flex",
        )}
        aria-label="Conversations"
      >
        <div className="flex flex-col gap-3 border-b border-line-1 px-4 py-4">
          <PageHeader
            title="Messages"
            icon={navIcon("messages")}
            helpId="tab.messages"
            sub={`Between you and the admins of ${orgName}.`}
          />
          <div className="flex items-center justify-between gap-2">
            <SegmentedControl<StatusFilter>
              size="sm"
              value={status}
              onChange={setStatus}
              options={[
                { value: "all", label: "All" },
                { value: "open", label: "Open" },
                { value: "closed", label: "Closed" },
              ]}
            />
            {data!.ask_allowed && (
              <Button variant="primary" size="sm" iconLeft={Plus} onClick={() => select({ compose: "1" })}>
                Ask my admin
              </Button>
            )}
          </div>
        </div>
        {/* At phone width the list is all there is until a conversation
            opens, so the offline banner shows here too, not only in the
            conversation pane. */}
        {banner && (
          <div className="px-4 pt-3 lg:hidden">
            <RailBanner banner={banner} />
          </div>
        )}
        {rows.length === 0 ? (
          <div className="px-4 py-8 text-center text-[12px] text-fg-3">
            {status === "closed" ? "No closed conversations." : "No conversations yet."}
          </div>
        ) : (
          <ul className="flex-1" role="list">
            {rows.map((r) => (
              <ThreadListItem key={r.key} row={r} active={selected === (r.threadId ?? r.key)} />
            ))}
          </ul>
        )}
        <SurfacesCard surfaces={data!.surfaces} />
      </aside>

      {/* The detail. At phone width it shows only when something is picked. */}
      <section className={clsx("min-w-0 flex-1 flex-col", selected ? "flex" : "hidden lg:flex")} aria-label="Conversation">
        {banner && (
          <div className="px-4 pt-4 sm:px-6">
            <RailBanner banner={banner} />
          </div>
        )}
        {composing ? (
          <AskForm
            data={data!}
            onCancel={() => select(null)}
            onSent={(item) => {
              refreshAfterWrite([page.reload]);
              select(item.result_thread_id ? { thread: item.result_thread_id } : { pending: item.id });
            }}
          />
        ) : threadId ? (
          <ThreadView
            key={threadId}
            threadId={threadId}
            orgName={orgName}
            focusReply={replyFocus}
            onBack={() => select(null)}
            onChanged={() => refreshAfterWrite([page.reload])}
          />
        ) : pendingId ? (
          <PendingThreadView
            item={data!.pending_threads.find((p) => p.id === pendingId) ?? null}
            token={data!.confirm_token}
            onBack={() => select(null)}
            onChanged={() => refreshAfterWrite([page.reload])}
            onGone={() => {
              refreshAfterWrite([page.reload]);
              select(null);
            }}
          />
        ) : (
          <NoneSelected
            empty={rows.length === 0}
            orgName={orgName}
            askAllowed={data!.ask_allowed}
            onAsk={() => navigate("/messages?compose=1")}
          />
        )}
      </section>
    </div>
  );
}

// RailBanner says the org server cannot be reached (or has not answered
// yet), with when it last did.
function RailBanner({ banner }: { banner: NonNullable<ReturnType<typeof railBanner>> }) {
  return (
    <Callout tone={banner.tone} title={banner.title} icon={banner.tone === "warn" ? WifiOff : Clock}>
      {banner.body}
    </Callout>
  );
}

// ---------- list ----------

function Avatar({ text, tone = "accent", size = 28 }: { text: string; tone?: "accent" | "you"; size?: number }) {
  return (
    <span
      aria-hidden
      style={{ width: size, height: size }}
      className={clsx(
        "grid shrink-0 place-items-center rounded-pill text-[10px] font-semibold",
        tone === "accent" ? "bg-accent text-accent-on" : "bg-bg-4 text-fg-1",
      )}
    >
      {text}
    </span>
  );
}

function ThreadListItem({ row, active }: { row: ListRow; active: boolean }) {
  const to = row.threadId ? `/messages?thread=${encodeURIComponent(row.threadId)}` : `/messages?pending=${encodeURIComponent(row.outboxId ?? "")}`;
  const kind = kindView(row.kind);
  return (
    <li>
      <Link
        to={to}
        aria-current={active ? "true" : undefined}
        className={clsx(
          "relative flex gap-2.5 border-b border-line-1 px-4 py-3 transition-colors focus:outline-none focus-visible:bg-bg-2",
          active ? "bg-bg-2" : "hover:bg-bg-2",
        )}
      >
        {active && <span aria-hidden className="absolute inset-y-0 left-0 w-[2px] bg-accent" />}
        <span className="mt-2 w-2 shrink-0">
          {row.unread && <span aria-label="Unread" className="block h-2 w-2 rounded-pill bg-accent" />}
        </span>
        <Avatar text={row.initials} tone={row.startedByYou ? "you" : "accent"} />
        <span className="min-w-0 flex-1">
          <span className="flex items-baseline justify-between gap-2">
            <span className={clsx("truncate text-[12.5px]", row.unread ? "font-semibold text-fg-0" : "text-fg-1")}>{row.subject}</span>
            <span className="shrink-0 text-[10.5px] tabular-nums text-fg-3">{listTime(row.at)}</span>
          </span>
          {row.preview && <span className="mt-0.5 block truncate text-[11.5px] text-fg-3">{row.preview}</span>}
          <span className="mt-1.5 flex flex-wrap gap-1">
            {row.kind !== "note" && (
              <Pill variant={kind.tone} case="none">
                {kind.label}
              </Pill>
            )}
            {row.topic && (
              <Pill variant="neutral" case="none">
                {topicLabel(row.topic)}
              </Pill>
            )}
            {row.needsAck && (
              <Pill variant="warn" case="none">
                Please acknowledge
              </Pill>
            )}
            {row.startedByYou && (
              <Pill variant="info" case="none">
                Started by you
              </Pill>
            )}
            {row.queued && (
              <Pill variant="warn" case="none" icon={Clock}>
                Queued
              </Pill>
            )}
            {row.failed && (
              <Pill variant="danger" case="none" icon={X}>
                Not sent
              </Pill>
            )}
            {row.closed && (
              <Pill variant="neutral" case="none" icon={Lock}>
                Closed
              </Pill>
            )}
          </span>
        </span>
      </Link>
    </li>
  );
}

const SURFACE_ROWS: { key: keyof MessagesSurfaces; label: string }[] = [
  { key: "toast", label: "Toast while the dashboard is open" },
  { key: "vscode", label: "VS Code notification" },
  { key: "statusline", label: "Status line hint" },
  { key: "desktop", label: "Desktop notification" },
  { key: "alerts_only", label: "Alerts only, mute notes and coaching" },
];

function SurfacesCard({ surfaces }: { surfaces: MessagesSurfaces }) {
  return (
    <details className="group mt-auto border-t border-line-1 px-4 py-3 text-[11.5px]">
      <summary className="cursor-pointer select-none text-fg-2 hover:text-fg-1">Where messages show up</summary>
      <ul className="mt-2 space-y-1.5">
        <li className="flex items-center justify-between gap-2 text-fg-2">
          <span>This page and the bell</span>
          <Pill variant="success" case="none">
            Always on
          </Pill>
        </li>
        {SURFACE_ROWS.map((s) => (
          <li key={s.key} className="flex items-center justify-between gap-2 text-fg-2">
            <span>{s.label}</span>
            <Pill variant={surfaces[s.key] ? "success" : "neutral"} case="none">
              {surfaces[s.key] ? "On" : "Off"}
            </Pill>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[11px] text-fg-3">
        Your organization cannot turn these on for you, and muting a surface never hides a message from this page.
      </p>
      <Link to={SETTINGS_MESSAGES_LINK} className="mt-1.5 inline-block text-[11.5px] text-accent hover:underline">
        Change where messages show up
      </Link>
    </details>
  );
}

// ---------- empty, loading and not-ready states ----------

function PageSkeleton() {
  return (
    <div className="flex min-h-full" role="status" aria-label="Loading messages">
      <div className="w-full space-y-3 border-r border-line-1 p-4 lg:w-[340px]">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-3 w-56" />
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex gap-2.5 pt-3">
            <Skeleton className="h-7 w-7 rounded-pill" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3 w-3/4" />
              <Skeleton className="h-3 w-1/2" />
            </div>
          </div>
        ))}
      </div>
      <div className="hidden flex-1 space-y-3 p-6 lg:block">
        <Skeleton className="h-5 w-64" />
        <Skeleton className="h-24 w-full max-w-2xl" />
      </div>
    </div>
  );
}

function NotReady({ state, orgName }: { state: "not_enrolled" | "not_supported" | "channel_off"; orgName: string }) {
  const content: Record<typeof state, { icon: LucideIcon; title: string; body: string; to?: string; toLabel?: string }> = {
    not_enrolled: {
      icon: Lock,
      title: "Messages need an organization",
      body: "This machine is not enrolled with a team, so there is nobody to write to you. Messages are a team feature.",
      to: "/settings?section=enrolment",
      toLabel: "Join an organization",
    },
    not_supported: {
      icon: Unplug,
      title: "Your organization's server does not support messages yet",
      body: `Messages start arriving once ${orgName} updates its Observer server. Nothing is lost in the meantime. Requests still reach your admins.`,
      to: "/requests",
      toLabel: "Open Requests",
    },
    channel_off: {
      icon: MessagesSquare,
      title: "Messages are turned off for your organization",
      body: `The admins of ${orgName} turned messaging off. Requests still reach them.`,
      to: "/requests",
      toLabel: "Open Requests",
    },
  };
  const c = content[state];
  return (
    <div className="flex min-h-full items-start justify-center p-4 sm:p-10">
      <div className="w-full max-w-lg">
        <EmptyState icon={c.icon} title={c.title} body={c.body} to={c.to} toLabel={c.toLabel} helpId="tab.messages" />
      </div>
    </div>
  );
}

function NoneSelected({ empty, orgName, askAllowed, onAsk }: { empty: boolean; orgName: string; askAllowed: boolean; onAsk: () => void }) {
  return (
    <div className="flex flex-1 items-start justify-center p-6 sm:p-10">
      <div className="w-full max-w-md">
        <EmptyState
          icon={MessagesSquare}
          title={empty ? "No messages" : "Pick a conversation"}
          body={
            empty
              ? `When an admin at ${orgName} writes to you, it shows up here and in the bell.${askAllowed ? " You can also start a conversation." : ""}`
              : "Choose a conversation on the left to read it and reply."
          }
        >
          {askAllowed && (
            <Button variant="primary" size="sm" iconLeft={Plus} onClick={onAsk}>
              Ask my admin
            </Button>
          )}
        </EmptyState>
      </div>
    </div>
  );
}

// ---------- one conversation ----------

function ThreadView({
  threadId,
  orgName,
  focusReply,
  onBack,
  onChanged,
}: {
  threadId: string;
  orgName: string;
  focusReply: boolean;
  onBack: () => void;
  onChanged: () => void;
}) {
  const t = useApi<ThreadResponse>(`/api/messages/threads/${encodeURIComponent(threadId)}`, undefined, [threadId], {
    refreshMs: POLL_MS,
  });
  const data = t.data;
  const [notice, setNotice] = useState<string | null>(null);
  const [acking, setAcking] = useState(false);
  const markedFor = useRef<string | null>(null);

  // Opening a conversation marks it read (and queues read receipts when the
  // org has them on). Once per thread id per mount; a newly arrived message
  // is marked on the next open.
  const unread = data?.thread.unread ?? 0;
  const token = data?.confirm_token ?? "";
  useEffect(() => {
    if (!data || unread <= 0 || markedFor.current === threadId) return;
    markedFor.current = threadId;
    void postJSON(`/api/messages/threads/${encodeURIComponent(threadId)}/read`, {}, token)
      .then(() => onChanged())
      .catch(() => {
        markedFor.current = null;
      });
  }, [data, unread, threadId, token, onChanged]);

  // A message that arrives while the conversation is open scrolls into view;
  // the first render does not, so the header and its Back button stay on
  // screen when a conversation opens.
  const bottomRef = useRef<HTMLDivElement>(null);
  const count = data?.messages.length ?? 0;
  const prevCount = useRef(-1);
  useEffect(() => {
    if (prevCount.current >= 0 && count > prevCount.current) {
      bottomRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
    if (count > 0 || prevCount.current >= 0) prevCount.current = count;
  }, [count]);

  if (t.loading && !data) {
    return (
      <div className="space-y-3 p-6" role="status" aria-label="Loading conversation">
        <Skeleton className="h-5 w-72" />
        <Skeleton className="h-28 w-full max-w-2xl" />
      </div>
    );
  }
  if (t.status === 404) {
    return (
      <div className="p-6">
        <BackButton onBack={onBack} />
        <EmptyState icon={MessagesSquare} title="Conversation not found" body="It may have been removed under your organization's retention rules." />
      </div>
    );
  }
  if (!data) {
    return (
      <div className="p-6">
        <BackButton onBack={onBack} />
        <ErrorState title="The conversation could not load" error={t.error} onRetry={t.reload} />
      </div>
    );
  }

  const th = data.thread;
  const ask = pendingAck(data.messages);
  const unsent = unsentPosts(data.outbox, data.messages);
  const kind = kindView(th.kind);
  const firstAdmin = data.messages.find((m) => m.author_kind === "admin");
  const closed = th.status === "closed";
  const footer = readReceiptNote(data.read_receipts);

  const acknowledge = async () => {
    if (!ask) return;
    setAcking(true);
    setNotice(null);
    try {
      await postJSON(`/api/messages/${ask.id}/ack`, {}, token);
      t.reload();
      onChanged();
    } catch (e) {
      setNotice(`Could not acknowledge: ${errorText(e)}`);
    } finally {
      setAcking(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col">
      <header className="border-b border-line-1 px-4 py-4 sm:px-6">
        <BackButton onBack={onBack} />
        <h2 className="text-[16px] font-semibold text-fg-0">{th.subject || "(no subject)"}</h2>
        <p className="mt-1 flex flex-wrap items-center gap-1.5 text-[12px] text-fg-3">
          {th.started_by === "developer" ? (
            <span>You started this conversation with the admins of {orgName}</span>
          ) : (
            <span>
              From {firstAdmin?.author_name || "an admin"}, admin at {orgName}
            </span>
          )}
          {th.kind !== "note" && (
            <Pill variant={kind.tone} case="none">
              {kind.label}
            </Pill>
          )}
          {th.topic && (
            <Pill variant="neutral" case="none">
              {topicLabel(th.topic)}
            </Pill>
          )}
          {closed && (
            <Pill variant="neutral" case="none" icon={Lock}>
              Closed
            </Pill>
          )}
        </p>
      </header>

      <div className="flex-1 space-y-5 px-4 py-5 sm:px-6">
        {data.messages.map((m) => (
          <MessageBlock key={m.id} m={m} />
        ))}
        {unsent.map((o) => (
          <OutboxBlock key={o.id} item={o} token={token} onChanged={() => {
              t.reload();
              onChanged();
            }} />
        ))}
        {ask && (
          <div className="flex flex-col gap-2 rounded-3 border border-accent/40 bg-accent-soft px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <span className="flex items-center gap-2 text-[12.5px] text-fg-1">
              <Icon icon={Hand} size="sm" className="shrink-0 text-accent" />
              {ackPrompt(ask)}
            </span>
            <Button variant="primary" size="sm" iconLeft={Check} loading={acking} onClick={() => void acknowledge()}>
              Acknowledge
            </Button>
          </div>
        )}
        {notice && (
          <Callout tone="danger" title="Something went wrong.">
            {notice}
          </Callout>
        )}
        {closed && (
          <Callout tone="info" title="An admin closed this conversation.">
            You can still read it. To ask something new, start a new conversation.
          </Callout>
        )}
        {footer && <p className="text-[11px] text-fg-3">{footer}</p>}
        <div ref={bottomRef} />
      </div>

      {!closed && (
        <Composer
          threadId={threadId}
          token={token}
          autoFocus={focusReply}
          onSent={() => {
            t.reload();
            onChanged();
          }}
        />
      )}
    </div>
  );
}

function BackButton({ onBack }: { onBack: () => void }) {
  return (
    <button
      type="button"
      onClick={onBack}
      className="mb-2 inline-flex items-center gap-1 text-[12px] text-accent hover:underline lg:hidden"
    >
      <Icon icon={ArrowLeft} size="xs" /> All conversations
    </button>
  );
}

function MessageBlock({ m }: { m: InboxMessage }) {
  const you = m.author_kind === "developer";
  const atts = m.attachments ?? [];
  return (
    <article className="flex gap-3" aria-label={`${you ? "You" : m.author_name} at ${fmtDateTime(m.created_at)}`}>
      <Avatar text={you ? "Y" : initials(m.author_name)} tone={you ? "you" : "accent"} size={32} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 text-[11.5px]">
          <b className="text-fg-0">{you ? "You" : m.author_name || "Admin"}</b>
          {!you && <span className="text-fg-3">admin</span>}
          <Tooltip content={fmtDateTime(m.created_at)}>
            <time dateTime={m.created_at} className="text-fg-3">
              {listTime(m.created_at)}
            </time>
          </Tooltip>
          {m.acked_at && (
            <Pill variant="success" case="none" icon={Check}>
              Acknowledged
            </Pill>
          )}
        </div>
        <div
          className={clsx(
            "mt-1 max-w-3xl rounded-3 border px-3.5 py-2.5",
            you ? "border-accent/25 bg-accent-soft" : "border-line-2 bg-bg-1",
          )}
        >
          <p className="whitespace-pre-wrap break-words text-[13px] leading-relaxed text-fg-1">{m.body}</p>
          {atts.length > 0 && <AttachmentCards list={atts} />}
        </div>
        {atts.length > 0 && !you && (
          <p className="mt-1 text-[11px] text-fg-3">The cards open your own copy on this machine.</p>
        )}
      </div>
    </article>
  );
}

function AttachmentCards({ list, onRemove }: { list: MessageAttachment[]; onRemove?: (a: MessageAttachment) => void }) {
  return (
    <div className="mt-2.5 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
      {list.map((a) => {
        const v = attachmentView(a);
        const body = (
          <>
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded-2 bg-accent-soft text-accent">
              <Icon icon={ATTACH_ICON[v.icon]} size="sm" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[12px] text-fg-1">{v.title}</span>
              <span className="block truncate text-[11px] text-fg-3">{v.sub}</span>
            </span>
          </>
        );
        return onRemove ? (
          <div key={`${a.type}:${a.ref}`} className="flex items-center gap-2.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-2">
            {body}
            <button
              type="button"
              aria-label={`Remove ${v.title}`}
              onClick={() => onRemove(a)}
              className="grid h-5 w-5 place-items-center rounded-1 text-fg-3 hover:bg-bg-3 hover:text-fg-0"
            >
              <Icon icon={X} size={11} />
            </button>
          </div>
        ) : (
          <Link
            key={`${a.type}:${a.ref}`}
            to={v.to}
            className="flex items-center gap-2.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-2 transition-colors hover:border-accent/40 hover:bg-bg-3"
          >
            {body}
          </Link>
        );
      })}
    </div>
  );
}

// ---------- the developer's waiting posts ----------

function OutboxBlock({ item, token, onChanged, onGone }: { item: OutboxItem; token: string; onChanged: () => void; onGone?: () => void }) {
  const v = outboxView(item);
  const [busy, setBusy] = useState<"retry" | "discard" | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const run = async (what: "retry" | "discard") => {
    setBusy(what);
    setNote(null);
    try {
      await postJSON(`/api/messages/outbox/${encodeURIComponent(item.id)}/${what}`, {}, token);
      if (what === "discard" && onGone) onGone();
      else onChanged();
    } catch (e) {
      setNote(errorText(e));
    } finally {
      setBusy(null);
    }
  };
  const copy = async () => {
    const r = await writeClipboard(item.body ?? "");
    setNote(r === "failed" ? "Could not copy; select the text and copy it by hand." : "Copied.");
  };
  return (
    <article className="flex gap-3" aria-label="Your message, not yet stored by your organization">
      <Avatar text="Y" tone="you" size={32} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 text-[11.5px]">
          <b className="text-fg-0">You</b>
          <span className="text-fg-3">{listTime(item.created_at)}</span>
          <Pill variant={v.tone === "danger" ? "danger" : v.tone === "warn" ? "warn" : "info"} case="none" icon={v.tone === "danger" ? X : Clock}>
            {v.pill}
          </Pill>
        </div>
        <div className="mt-1 max-w-3xl rounded-3 border border-accent/25 bg-accent-soft px-3.5 py-2.5">
          <p className="whitespace-pre-wrap break-words text-[13px] leading-relaxed text-fg-1">{item.body}</p>
          {(item.attachments ?? []).length > 0 && <AttachmentCards list={item.attachments ?? []} />}
        </div>
        <p className={clsx("mt-1 text-[11px]", v.tone === "danger" ? "text-danger" : "text-fg-3")}>{v.note}</p>
        {item.state !== "sent" && (
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {v.canRetry && (
              <Button size="sm" loading={busy === "retry"} onClick={() => void run("retry")}>
                Retry now
              </Button>
            )}
            <Button size="sm" onClick={() => void copy()}>
              Copy text
            </Button>
            <Button size="sm" variant="ghost" loading={busy === "discard"} onClick={() => void run("discard")}>
              Discard
            </Button>
          </div>
        )}
        {note && <p className="mt-1 text-[11px] text-fg-3" role="status">{note}</p>}
      </div>
    </article>
  );
}

function PendingThreadView({
  item,
  token,
  onBack,
  onChanged,
  onGone,
}: {
  item: OutboxItem | null;
  token: string;
  onBack: () => void;
  onChanged: () => void;
  onGone: () => void;
}) {
  if (!item) {
    return (
      <div className="p-6">
        <BackButton onBack={onBack} />
        <EmptyState
          icon={MessagesSquare}
          title="This conversation moved"
          body="Your organization stored it, or it was discarded. Find it in the list on the left."
        />
      </div>
    );
  }
  return (
    <div className="flex flex-1 flex-col">
      <header className="border-b border-line-1 px-4 py-4 sm:px-6">
        <BackButton onBack={onBack} />
        <h2 className="text-[16px] font-semibold text-fg-0">{item.new_subject || "(no subject)"}</h2>
        <p className="mt-1 flex flex-wrap items-center gap-1.5 text-[12px] text-fg-3">
          <span>A conversation you started</span>
          {item.new_topic && (
            <Pill variant="neutral" case="none">
              {topicLabel(item.new_topic)}
            </Pill>
          )}
        </p>
      </header>
      <div className="flex-1 px-4 py-5 sm:px-6">
        <OutboxBlock item={item} token={token} onChanged={onChanged} onGone={onGone} />
      </div>
    </div>
  );
}

// ---------- composer ----------

/** Drafts kept per conversation for the life of the page, so switching
 *  conversations never loses a half-written reply. */
const drafts = new Map<string, { body: string; attachments: MessageAttachment[] }>();

function Composer({ threadId, token, autoFocus, onSent }: { threadId: string; token: string; autoFocus: boolean; onSent: () => void }) {
  const saved = drafts.get(threadId);
  const [body, setBody] = useState(saved?.body ?? "");
  const [attachments, setAttachments] = useState<MessageAttachment[]>(saved?.attachments ?? []);
  const [picker, setPicker] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    drafts.set(threadId, { body, attachments });
  }, [threadId, body, attachments]);
  useEffect(() => {
    if (autoFocus) document.getElementById(COMPOSER_ID)?.focus();
  }, [autoFocus]);

  const check = checkDraft({ body, attachments }, false);
  const send = async () => {
    if (!check.ok || sending) return;
    setSending(true);
    setError(null);
    try {
      await postJSON<{ item: OutboxItem }>(
        PAGE_PATH,
        { client_msg_id: newClientMsgId(), thread_id: threadId, body: body.trim(), attachments },
        token,
      );
      setBody("");
      setAttachments([]);
      drafts.delete(threadId);
      onSent();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="border-t border-line-1 bg-bg-1 px-4 py-3 sm:px-6">
      <label htmlFor={COMPOSER_ID} className="sr-only">
        Reply
      </label>
      <Textarea
        id={COMPOSER_ID}
        rows={3}
        value={body}
        placeholder="Write a reply. Ctrl+Enter sends."
        maxLength={8000}
        onChange={(e) => setBody(e.target.value)}
        onKeyDown={(e) => {
          if (isSendShortcut(e)) {
            e.preventDefault();
            void send();
          }
        }}
        className="w-full"
      />
      {attachments.length > 0 && (
        <AttachmentCards list={attachments} onRemove={(a) => setAttachments((l) => l.filter((x) => !(x.type === a.type && x.ref === a.ref)))} />
      )}
      {error && <p className="mt-1.5 text-[11.5px] text-danger" role="alert">{error}</p>}
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
        <Button size="sm" iconLeft={Paperclip} onClick={() => setPicker(true)}>
          Attach
        </Button>
        <span className="flex items-center gap-3">
          <span className="hidden text-[11px] text-fg-3 sm:inline">Your admins see this reply</span>
          <Button variant="primary" size="sm" iconLeft={Send} loading={sending} disabled={!check.ok} onClick={() => void send()}>
            Reply
          </Button>
        </span>
      </div>
      <AttachPicker
        open={picker}
        onClose={() => setPicker(false)}
        onPick={(a) => setAttachments((l) => addAttachment(l, a))}
        picked={attachments}
      />
    </div>
  );
}

// ---------- attach picker ----------

type PickTab = "sessions" | "projects" | "budgets";

function AttachPicker({
  open,
  onClose,
  onPick,
  picked,
}: {
  open: boolean;
  onClose: () => void;
  onPick: (a: MessageAttachment) => void;
  picked: MessageAttachment[];
}) {
  const [tab, setTab] = useState<PickTab>("sessions");
  const sessions = useApi<SessionsResponse>(open && tab === "sessions" ? "/api/sessions" : null, { page: 1, limit: 20 }, [open, tab]);
  const projects = useApi<ProjectsResponse>(open && tab === "projects" ? "/api/projects" : null, undefined, [open, tab]);
  const budgets = useApi<{ budgets?: RequestableBudget[] }>(open && tab === "budgets" ? "/api/requests" : null, undefined, [open, tab]);

  let options: AttachOption[] = [];
  let loading = false;
  let error: Error | null = null;
  if (tab === "sessions") {
    options = sessionOptions(sessions.data?.rows ?? [], (iso) => fmtClock(iso));
    loading = sessions.loading;
    error = sessions.error;
  } else if (tab === "projects") {
    options = projectOptions(projects.data?.rows ?? []);
    loading = projects.loading;
    error = projects.error;
  } else {
    options = budgetAttachOptions(budgets.data?.budgets ?? [], scopeWords);
    loading = budgets.loading;
    error = budgets.error;
  }
  const isPicked = (a: MessageAttachment) => picked.some((p) => p.type === a.type && p.ref === a.ref);
  const empty: Record<PickTab, string> = {
    sessions: "No sessions captured on this machine yet.",
    projects: "No projects on this machine yet.",
    budgets: "Your organization has not set a budget that applies to you.",
  };

  return (
    <Modal open={open} onClose={onClose} title="Attach from this machine" subtitle="A link to your own copy. No content is sent." icon={Paperclip}>
      <SegmentedControl<PickTab>
        size="sm"
        value={tab}
        onChange={setTab}
        options={[
          { value: "sessions", label: "Sessions" },
          { value: "projects", label: "Projects" },
          { value: "budgets", label: "Budgets" },
        ]}
      />
      <div className="mt-3 max-h-[50vh] overflow-y-auto">
        {loading ? (
          <div className="space-y-2">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : error ? (
          <ErrorState error={error} />
        ) : options.length === 0 ? (
          <p className="py-6 text-center text-[12px] text-fg-3">{empty[tab]}</p>
        ) : (
          <ul className="space-y-1.5">
            {options.map((o) => {
              const on = isPicked(o.attachment);
              return (
                <li key={o.key}>
                  <button
                    type="button"
                    disabled={on}
                    onClick={() => {
                      onPick(o.attachment);
                      onClose();
                    }}
                    className={clsx(
                      "flex w-full items-center gap-2.5 rounded-2 border px-3 py-2 text-left transition-colors",
                      on ? "border-line-1 bg-bg-1 text-fg-4" : "border-line-2 bg-bg-2 hover:border-accent/40 hover:bg-bg-3",
                    )}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[12px] text-fg-1">{o.title}</span>
                      <span className="block truncate text-[11px] text-fg-3">{o.sub}</span>
                    </span>
                    {on && <Pill case="none">Attached</Pill>}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Modal>
  );
}

// ---------- Ask my admin ----------

const TOPIC_ICON: Record<string, LucideIcon> = {
  budget: Wallet,
  model: Cpu,
  access: Lock,
  guard: ShieldAlert,
};

function AskForm({ data, onCancel, onSent }: { data: MessagesPageResponse; onCancel: () => void; onSent: (item: OutboxItem) => void }) {
  const topics = offeredTopics(data.policy);
  const [topic, setTopic] = useState<string>("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [attachments, setAttachments] = useState<MessageAttachment[]>([]);
  const [picker, setPicker] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tried, setTried] = useState(false);
  const orgName = data.org_name || "your organization";

  if (!data.ask_allowed) {
    const why = !data.policy
      ? "Your organization has not told this machine yet whether you can start conversations. That arrives with the next sync."
      : "Your organization does not let you start conversations. When an admin writes to you, you can reply. For an exception, file a request.";
    return (
      <div className="p-6">
        <BackButton onBack={onCancel} />
        <EmptyState icon={MessagesSquare} title="You cannot start a conversation here" body={why} to="/requests" toLabel="Open Requests" />
      </div>
    );
  }

  const check = checkDraft({ body, subject, topic, attachments }, true);
  const requestLink = requestLinkFor(topic, data.policy);
  const hasSession = attachments.some((a) => a.type === "session");
  const send = async () => {
    setTried(true);
    if (!check.ok || sending) return;
    setSending(true);
    setError(null);
    try {
      const r = await postJSON<{ item: OutboxItem }>(
        PAGE_PATH,
        { client_msg_id: newClientMsgId(), subject: subject.trim(), topic, body: body.trim(), attachments },
        data.confirm_token,
      );
      if (r?.item) onSent(r.item);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="p-4 sm:p-6">
      <BackButton onBack={onCancel} />
      <div className="max-w-2xl rounded-3 border border-line-2 bg-bg-1">
        <div className="border-b border-line-1 px-4 py-3">
          <h2 className="text-[15px] font-semibold text-fg-0">Ask my admin</h2>
          <p className="text-[11.5px] text-fg-3">Goes to the admins of {orgName}. They reply here.</p>
        </div>
        <form
          className="space-y-4 px-4 py-4"
          onSubmit={(e) => {
            e.preventDefault();
            void send();
          }}
        >
          <fieldset>
            <legend className="mb-1.5 text-[11.5px] text-fg-2">About</legend>
            <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Topic">
              {topics.map((t) => {
                const on = topic === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    role="radio"
                    aria-checked={on}
                    onClick={() => setTopic(t.id)}
                    className={clsx(
                      "inline-flex items-center gap-1.5 rounded-pill border px-3 py-1 text-[12px] transition-colors",
                      on ? "border-accent bg-accent-soft text-accent" : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-1",
                    )}
                  >
                    {TOPIC_ICON[t.id] && <Icon icon={TOPIC_ICON[t.id]!} size="xs" />}
                    {t.label}
                  </button>
                );
              })}
            </div>
            {tried && !topic && <p className="mt-1 text-[11px] text-danger">Pick what this is about.</p>}
            {requestLink && (
              <p className="mt-2 text-[11.5px] text-fg-3">
                Asking for more budget or access? A request goes to the admins as a decision they approve or decline.{" "}
                <Link to={requestLink} className="text-accent hover:underline">
                  File this as a request instead
                </Link>
              </p>
            )}
          </fieldset>
          <Input
            label="Subject"
            value={subject}
            maxLength={200}
            onChange={(e) => setSubject(e.target.value)}
            error={tried && !subject.trim() ? "Add a subject." : undefined}
            className="w-full"
          />
          <Textarea
            label="Message"
            rows={5}
            value={body}
            maxLength={8000}
            placeholder="Ctrl+Enter sends."
            onChange={(e) => setBody(e.target.value)}
            onKeyDown={(e) => {
              if (isSendShortcut(e)) {
                e.preventDefault();
                void send();
              }
            }}
            error={tried && !body.trim() ? "Write your question." : undefined}
            className="w-full"
          />
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-[11.5px] text-fg-2">Attach from this machine</span>
              <button type="button" className="inline-flex items-center gap-1 text-[11.5px] text-accent hover:underline" onClick={() => setPicker(true)}>
                <Icon icon={Plus} size="xs" /> Add
              </button>
            </div>
            {attachments.length === 0 ? (
              <p className="text-[11.5px] text-fg-3">Optional: a session, project or budget this is about.</p>
            ) : (
              <AttachmentCards list={attachments} onRemove={(a) => setAttachments((l) => l.filter((x) => !(x.type === a.type && x.ref === a.ref)))} />
            )}
            {hasSession && (
              <Callout tone="info" className="mt-2" title="No extra content is sent.">
                Your admins already see this session's metadata. Attaching links it to the question.
              </Callout>
            )}
          </div>
          {error && (
            <p className="text-[11.5px] text-danger" role="alert">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button size="md" onClick={onCancel}>
              Cancel
            </Button>
            <Button variant="primary" size="md" iconLeft={Send} loading={sending} onClick={() => void send()}>
              Send
            </Button>
          </div>
        </form>
      </div>
      <AttachPicker open={picker} onClose={() => setPicker(false)} onPick={(a) => setAttachments((l) => addAttachment(l, a))} picked={attachments} />
    </div>
  );
}
