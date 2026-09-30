// tokenSources — the ONE caption the session header's Tokens tile uses to
// name where its number came from, on the node dashboard and the org drawer
// alike (MCP audit #4b, 2026-09-27). Both servers compute the figure with the
// same rule (internal/sessionmsg.SumContributions over sessionmsg.Derive) and
// report the same two counts, so the two tiles only ever differ in the rows
// they hold - and the org names that boundary with an "as of" received time.
//
// Pure (no React, no fetch) so it runs under `node --test`.

import { fmtInt, fmtRelative } from "./format.ts";

export type TokenSourceCounts = {
  /** Usage rows behind the total after the proxy/transcript twin fold. */
  turns?: number | null;
  /** The proxy-observed subset of `turns`. */
  proxyTurns?: number | null;
};

const plural = (n: number, word: string) => `${fmtInt(n)} ${word}${n === 1 ? "" : "s"}`;

// tokenSourcesLine renders the counts as one short caption:
//   "3 proxy + 12 log turns" · "12 log turns · no proxy" · "3 proxy turns".
// Returns null when the counts are absent (an older server), so the caller
// keeps its previous caption instead of claiming a source it was not told.
export function tokenSourcesLine(c: TokenSourceCounts): string | null {
  if (c.turns == null || c.proxyTurns == null) return null;
  const turns = Math.max(0, c.turns);
  const proxy = Math.min(Math.max(0, c.proxyTurns), turns);
  const log = turns - proxy;
  if (turns === 0) return null;
  if (proxy === 0) return `${plural(log, "log turn")} · no proxy`;
  if (log === 0) return plural(proxy, "proxy turn");
  return `${fmtInt(proxy)} proxy + ${plural(log, "log turn")}`;
}

// receivedAsOfLine renders the org's honest "as of" for a node-pushed figure.
// null when the server sent no receive time.
export function receivedAsOfLine(
  lastReceivedAt: string | null | undefined,
  now: number = Date.now(),
): string | null {
  if (!lastReceivedAt) return null;
  return `as of ${fmtRelative(lastReceivedAt, now)}`;
}

// TOKENS_DEFINITION is the tile's tooltip text for a billed total.
export const TOKENS_DEFINITION =
  "Net input + cache read + cache write + output tokens. Proxy-captured turns and their transcript copies are counted once (the same rule on the developer's dashboard and the org dashboard).";

// ORG_RECEIVED_NOTE explains the org's "as of": the org holds what the node
// has pushed so far.
export const ORG_RECEIVED_NOTE =
  "This is what the developer's node has pushed so far. A running or just-finished session can read higher on the developer's own dashboard until the next push lands (every couple of minutes; a turn still being written can be held back up to 10 minutes).";
