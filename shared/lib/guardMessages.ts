// guardMessages — pure merge of guard-rail policy verdicts (hook-path
// deny/ask/flag events, guard_events / R-1xx rules) into a session's
// message timeline. Shared by the node dashboard (web/) and the org
// dashboard (web2/) Messages tabs — LOC/guardmsg/APM followups plan
// (docs/plans/loc-guardmsg-apm-followups-2026-09-21.md), Item 2.
//
// ONE algorithm, ONE owner (docs/app-design-system.md: never fork a shared
// concern into a parallel per-app implementation). Each app feeds its own
// message + guard-event shapes — which genuinely differ in what anchor data
// they carry (node resolves a real upstream message_id server-side; the org
// wire has none) — and gets back the same ordering rule. Pure data in, pure
// data out: no fetch, no React, no app-specific types.
//
// ONLY POLICY BLOCKS ARE EXPECTED HERE, NOT EVERY VERDICT — TOOL-CALL AND
// PROMPT-GUARD VERDICTS ALIKE (operator decision 2026-09-21, superseding
// the prior design which additionally excluded prompt-guard rows here).
// The caller (the node's /api/session/<id>/guard handler, and the org's
// client-side filter over the existing session-guard feed) is expected to
// pre-filter guardEvents down to enforced/deny/ask BEFORE calling this
// function — it does not filter by decision or event_kind itself. This
// merge is agnostic to which subsystem a block came from; each renderer
// (web's MessagesTab.tsx, web2's Sessions.tsx) labels prompt-guard rows
// (R-172 secrets / R-190 PII, event_kind=user_prompt where available)
// distinctly from tool-call verdicts after the merge, so the two read
// differently in the strip. On an observe-mode estate the surfaced blocks
// are today mostly prompt-guard rows (tool-call policy is still in
// flag/observe mode there) — that's expected. Interleaving every
// informational flag pill would still drown the timeline, which is why the
// pre-filter stays a hard requirement.
//
// ANCHOR RESOLUTION. guard_events has THREE producers with different
// anchors (see internal/store/guard.go GuardEventRow): the hook path
// (pre-execution deny/ask) sets no action_id at all; the proxy path anchors
// to api_turns.id; the watcher/post-hoc path anchors to actions.id. Live
// grounding found ~99% of tool-call events carry a resolvable action_id.
// The node endpoint resolves that action_id to the upstream
// actions.message_id SERVER-SIDE (a LEFT JOIN onto actions) and ships it as
// `message_id` — the exact key a rendered MessageRow already carries — so
// this function can place the event on the precise message it judged
// instead of guessing from timestamps. Events with no resolvable
// message_id (the small anchorless remainder, and every org event, which
// carries no anchor of any kind) fall back to nearest-timestamp placement.
// Timestamps are compared via Date.parse rather than string equality, so
// full-precision (RFC3339Nano) `ts` values matter for same-second ordering.

/** Minimal shape a guard event must have to be placed on a timeline. */
export interface GuardAnchor {
  ts: string;
  /**
   * The upstream message id (MessageRow.message_id) this verdict was
   * recorded against, resolved server-side from action_id -> actions
   * .message_id. Node-only in practice: the org wire
   * (`orgcontract.GuardEventRow`) has no node-local action_id to resolve,
   * so an org guard event is always undefined here and always falls
   * through to nearest-timestamp placement.
   */
  message_id?: string | null;
}

/** Minimal message shape the merge needs: its own timestamp and id. */
export interface MergeMessageLike {
  timestamp: string;
  message_id?: string;
}

export type TimelineEntry<M, G> =
  | { kind: "message"; ts: string; message: M }
  | { kind: "guard"; ts: string; event: G };

/**
 * mergeGuardIntoTimeline interleaves guardEvents into messages, returning
 * one chronologically-ordered list. Placement rule:
 *
 *  1. EXACT ANCHOR — a guard event whose message_id matches a loaded
 *     message's own message_id is placed immediately after that message:
 *     the verdict reads as "this happened while handling that turn".
 *  2. NEAREST TIMESTAMP — everything else (every org event, which carries
 *     no anchor at all; the small remainder of node events whose action_id
 *     didn't resolve to a message_id; and any message_id that isn't in the
 *     currently loaded window, e.g. a paginated view) is inserted
 *     immediately before the first message whose timestamp is >= the guard
 *     event's timestamp, or at the very end if none qualifies.
 *
 * Multiple guard events landing on the same insertion point keep guard-
 * event timestamp order relative to each other. Pure function: safe to
 * unit-test directly and to call on every render.
 */
export function mergeGuardIntoTimeline<M extends MergeMessageLike, G extends GuardAnchor>(
  messages: readonly M[],
  guardEvents: readonly G[],
): TimelineEntry<M, G>[] {
  if (guardEvents.length === 0) {
    return messages.map((message) => ({ kind: "message" as const, ts: message.timestamp, message }));
  }

  // message_id -> index of its (first) occurrence, for exact-anchor
  // placement. An empty message_id never anchors (some rows genuinely carry
  // none) and is excluded rather than mapped to the empty string.
  const messageIndex = new Map<string, number>();
  messages.forEach((m, i) => {
    if (m.message_id && !messageIndex.has(m.message_id)) messageIndex.set(m.message_id, i);
  });

  // Every guard event is bucketed by the message index it is placed AFTER;
  // -1 means "before every message". Anchored and timestamp-fallback events
  // share this one bucket space so the final assembly pass is a single walk.
  const buckets = new Map<number, G[]>();
  const bucket = (idx: number, ev: G) => {
    const arr = buckets.get(idx);
    if (arr) arr.push(ev);
    else buckets.set(idx, [ev]);
  };

  const msgMs = messages.map((m) => Date.parse(m.timestamp));
  for (const ev of guardEvents) {
    const anchor = ev.message_id ? messageIndex.get(ev.message_id) : undefined;
    if (anchor !== undefined) {
      bucket(anchor, ev);
      continue;
    }
    const evMs = Date.parse(ev.ts);
    let before = messages.length; // none qualifies -> after the last message
    for (let i = 0; i < msgMs.length; i++) {
      if (!Number.isNaN(msgMs[i]) && msgMs[i] >= evMs) {
        before = i;
        break;
      }
    }
    bucket(before - 1, ev);
  }

  // Stable-ish chronological order within a bucket. Date.parse over
  // RFC3339-ish strings handles the node/org endpoints' differing precision
  // (guard ts is second-precision; message timestamps may carry fractional
  // seconds) correctly, unlike a raw string compare.
  for (const arr of buckets.values()) {
    arr.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  }

  const out: TimelineEntry<M, G>[] = [];
  const emit = (idx: number) => {
    for (const ev of buckets.get(idx) ?? []) out.push({ kind: "guard", ts: ev.ts, event: ev });
  };
  emit(-1);
  messages.forEach((m, i) => {
    out.push({ kind: "message", ts: m.timestamp, message: m });
    emit(i);
  });
  return out;
}

/** One guard banner to render, with the seq of the nearest PRECEDING
 * message (if any) for a "after turn #N" backlink. Messages must expose
 * `seq` — both node's MessageRow and the org's MessageRowLike do. */
export interface GuardBanner<G> {
  event: G;
  afterSeq?: number;
}

/**
 * guardBannersWithContext runs mergeGuardIntoTimeline and strips the result
 * down to just the guard entries, each carrying the seq of the message it
 * landed after (undefined when it landed before every message). This is the
 * shape both apps' Messages-tab banner strip renders from — the merge
 * itself is an implementation detail neither renderer needs to see.
 *
 * NOTE: callers must pre-filter guardEvents down to actual policy blocks
 * (enforced, or decision in deny/ask) before calling this — see the file
 * header. This function does not filter by decision itself, and does not
 * distinguish tool-call from prompt-guard rows; that labelling is a
 * renderer-side concern applied after this returns.
 */
export function guardBannersWithContext<
  M extends MergeMessageLike & { seq: number },
  G extends GuardAnchor,
>(messages: readonly M[], guardEvents: readonly G[]): GuardBanner<G>[] {
  const merged = mergeGuardIntoTimeline(messages, guardEvents);
  const out: GuardBanner<G>[] = [];
  let afterSeq: number | undefined;
  for (const entry of merged) {
    if (entry.kind === "message") afterSeq = entry.message.seq;
    else out.push({ event: entry.event, afterSeq });
  }
  return out;
}
