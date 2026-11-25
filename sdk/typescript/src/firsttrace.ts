/**
 * The app's first-trace line (plan 3.8, ruling R12): once per process, after
 * the first root span is exported, one line on stderr with a link to the
 * trace: "superbased: first trace from this process: <link>". When the export
 * was refused by the organization's plan, the line says the refusal (its
 * message and upgrade link) in place of the link.
 *
 * Only when stderr is a terminal, `CI` is unset and
 * SUPERBASED_FIRST_TRACE_LINK is not off, so production logs stay quiet.
 *
 * Links (pure, {@link traceLink}): the local leg links this machine's
 * dashboard, `<node_url>/apps/traces?trace=<id>`, when the local exporter
 * sends to the machine (not to a collector the app named); the online leg
 * links `<dashboard_url>/trajectories?trace=<id>`, where the dashboard base
 * comes from the SDK-held file or the machine's discovery answer. No base
 * known: no line.
 */

import type { ReadableSpan } from "@opentelemetry/sdk-trace-base";

import { localEndpointNamed } from "./config.js";
import type { PlanRefusalError } from "./planrefusal.js";
import { runtime } from "./runtime.js";

/** The opt-out variable (`0`, `false`, `no` or `off` turns the line off). */
export const FIRST_TRACE_ENV = "SUPERBASED_FIRST_TRACE_LINK";
/** The line's prefix. */
export const FIRST_TRACE_PREFIX = "superbased: first trace from this process: ";

const OFF = ["0", "false", "no", "off"];

/** Whether the line may be written: stderr is a terminal, CI is unset (or empty, `0`, `false`), and the opt-out is not set. Pure. */
export function linkAllowed(isTTY: boolean, env: Record<string, string | undefined>): boolean {
  if (!isTTY) return false;
  const ci = (env.CI ?? "").trim().toLowerCase();
  if (ci !== "" && ci !== "0" && ci !== "false") return false;
  return !OFF.includes((env[FIRST_TRACE_ENV] ?? "").trim().toLowerCase());
}

/** The link for one leg ("" when no base is known). Pure. */
export function traceLink(leg: "local" | "online", traceId: string, nodeUrl: string, dashboardUrl: string): string {
  const id = encodeURIComponent(traceId);
  if (leg === "local") return nodeUrl ? `${nodeUrl.replace(/\/+$/, "")}/apps/traces?trace=${id}` : "";
  return dashboardUrl ? `${dashboardUrl.replace(/\/+$/, "")}/trajectories?trace=${id}` : "";
}

/** The line for a refused first trace: the server's message as sent, then the upgrade link when there is one. Pure. */
export function refusalLine(r: Pick<PlanRefusalError, "message" | "upgradeUrl">): string {
  return `superbased: traces from this process were refused: ${r.message}${r.upgradeUrl ? ` ${r.upgradeUrl}` : ""}`;
}

interface Sink {
  isTTY(): boolean;
  env(): Record<string, string | undefined>;
  write(line: string): void;
}

const processSink: Sink = {
  isTTY: () => typeof process !== "undefined" && process.stderr?.isTTY === true,
  env: () => (typeof process !== "undefined" ? process.env : {}) as Record<string, string | undefined>,
  write: (line) => {
    try {
      process.stderr.write(line + "\n");
    } catch {
      // a closed stderr must not break export
    }
  },
};

let sink: Sink = processSink;
let done = false;
let written = "";
/** Under `both`: per trace, the outcome of each leg so far. */
const legs = new Map<string, { local?: boolean; online?: boolean }>();

/** The trace id of the first root span in a batch ("" when none is a root). */
export function rootTraceId(spans: readonly ReadableSpan[]): string {
  for (const s of spans) {
    const parent = (s as unknown as { parentSpanContext?: { spanId?: string }; parentSpanId?: string }).parentSpanContext?.spanId ??
      (s as unknown as { parentSpanId?: string }).parentSpanId;
    if (!parent) return s.spanContext().traceId;
  }
  return "";
}

/** The link for a leg as this process is configured ("" when none can be built). */
function linkFor(leg: "local" | "online", traceId: string): string {
  const s = runtime.settings;
  if (!s) return "";
  if (leg === "local") {
    // A collector the app named is not this machine's dashboard.
    if (localEndpointNamed(s, runtime.destination)) return "";
    return traceLink("local", traceId, s.nodeUrl, "");
  }
  return traceLink("online", traceId, "", runtime.dashboardUrl);
}

function write(line: string): void {
  done = true;
  written = line;
  legs.clear();
  sink.write(line);
}

/**
 * Decide for one trace once its legs are known. Under `both` the online link
 * wins when its base is known and the online export succeeded; else the
 * local link (section 16).
 */
function decide(traceId: string, got: { local?: boolean; online?: boolean }): void {
  const online = linkFor("online", traceId);
  const local = linkFor("local", traceId);
  if (runtime.destination === "both") {
    if (got.online && online) return write(FIRST_TRACE_PREFIX + online);
    // Wait for the online leg while it could still win.
    if (online && got.online === undefined) return;
    if (got.local && local) return write(FIRST_TRACE_PREFIX + local);
    return;
  }
  if (got.online && online) return write(FIRST_TRACE_PREFIX + online);
  if (got.local && local) return write(FIRST_TRACE_PREFIX + local);
}

/** An export of `spans` to `leg` ended: write the line once, when there is a root span and a link. */
export function noteExported(spans: readonly ReadableSpan[], leg: "local" | "online", ok = true): void {
  if (done) return;
  try {
    const id = rootTraceId(spans);
    if (!id) return;
    if (!linkAllowed(sink.isTTY(), sink.env())) {
      done = true; // the conditions hold for the process; nothing to retry
      return;
    }
    const got = { ...(legs.get(id) ?? {}), [leg]: ok };
    legs.set(id, got);
    if (legs.size > 64) legs.delete(legs.keys().next().value as string);
    decide(id, got);
  } catch {
    // never break export
  }
}

/** An export carrying a root span was refused by the plan: say so in place of the link, once. */
export function noteRefused(spans: readonly ReadableSpan[], refusal: PlanRefusalError | null): void {
  if (done || !refusal) return;
  try {
    if (!rootTraceId(spans)) return;
    if (!linkAllowed(sink.isTTY(), sink.env())) {
      done = true;
      return;
    }
    write(refusalLine(refusal));
  } catch {
    // never break export
  }
}

/** The line once written ("" before). */
export function firstTraceWritten(): string {
  return written.startsWith(FIRST_TRACE_PREFIX) ? written.slice(FIRST_TRACE_PREFIX.length) : written;
}

/** Tests: replace where the line goes and what it checks, and forget that it was written. */
export function _setFirstTraceSinkForTests(s: Partial<Sink> | null): void {
  sink = s ? { ...processSink, ...s } : processSink;
  done = false;
  written = "";
  legs.clear();
}

/** Tests: forget that the line was written. */
export function _resetFirstTraceForTests(): void {
  done = false;
  written = "";
  legs.clear();
}
