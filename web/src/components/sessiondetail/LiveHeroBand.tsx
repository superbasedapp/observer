import { HeroStat, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import { flattenProcs, networkSummary, utilPct, type SessionNetworkSummary } from "@/lib/cockpit";
import type {
  PredictResponse,
  SessionDetail,
  SessionProcessResponse,
} from "@/lib/types";

// LiveHeroBand — the four "what is happening RIGHT NOW" hero tiles, rendered
// at the very top of the session slide-over when it is opened from a live
// terminal (Task 9). Opt-in via SessionDetailPanel's `liveHero` prop: the
// page-level surfaces (Sessions / Actions / Cache / Live) keep the four
// historical KpiBand tiles as their headline and are untouched.
//
// WHY A SEPARATE BAND RATHER THAN MORE KpiBand TILES. KpiBand answers "what
// did this session cost and do" — totals, backward-looking, stable. These four
// answer "how much room is left and what will the next message cost" —
// forward-looking, and only meaningful while a session is still running. They
// are also sourced differently: KpiBand reads the detail rollup alone, while
// three of these four come from endpoints the shell does not fetch.
//
// FETCHING. `detail` is passed DOWN from the shell (which already polls
// /api/session/<id>) rather than re-fetched here. The predictor and the process
// tree are fetched here because the shell does not own them — the Cost and
// System tabs do, and those are LAZY-mounted, so on a panel the operator never
// tabs through there is exactly one poll of each. When those tabs are opened
// the poll is duplicated; that is the accepted cost of not hoisting two more
// fetches into a shell shared by five host pages that do not want them.
//
// EMPTY STATES ARE NAMED, NEVER FAKED. Every tile that cannot compute its
// number says which dependency is missing (no context budget reported / not
// routed through the proxy / no session history yet / process capture off)
// rather than rendering a zero. A zero here would be read as an observation.

export function LiveHeroBand({
  sessionId,
  detail,
  onPinVitals,
}: {
  sessionId: string;
  detail: SessionDetail | null;
  /**
   * Offered by the terminal host only: this slide-over covers the terminal it
   * was opened from, so "Pin vitals panel" hands the operator the small
   * floating cockpit that sits BESIDE the terminal instead. Absent ⇒ the
   * affordance is not rendered at all (rather than rendered inert).
   */
  onPinVitals?: () => void;
}) {
  // Same cadences the terminal cockpit uses for the same endpoints, so the two
  // surfaces never disagree about how fresh a number is.
  const predict = useApi<PredictResponse>(
    sessionId ? `/api/session/${sessionId}/predict` : null,
    undefined,
    [sessionId],
    { refreshMs: 15000 },
  );
  const procs = useApi<SessionProcessResponse>(
    sessionId ? `/api/session/${sessionId}/processes` : null,
    undefined,
    [sessionId],
    { refreshMs: 10000 },
  );
  const network = useApi<SessionNetworkSummary>(
    sessionId ? `/api/session/${sessionId}/network` : null,
    { summary: 1 },
    [sessionId],
    { refreshMs: 15000 },
  );

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <ContextWindowCard detail={detail} predict={predict.data} loading={predict.loading} />
        <LimitCard limit={predict.data?.limit} loading={predict.loading} />
        <NextTurnCostCard predict={predict.data} loading={predict.loading} />
        <SystemCard
          procs={procs.data}
          procsErr={procs.error != null}
          network={network.data}
          networkErr={network.error != null}
          loading={procs.loading && !procs.data}
        />
      </div>
      {onPinVitals && (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onPinVitals}
            title="Open the small floating vitals cockpit, which sits beside the terminal instead of covering it"
            className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
          >
            ⊙ Pin vitals panel
          </button>
        </div>
      )}
    </div>
  );
}

// ── 1: context window used ──────────────────────────────────────────────────
//
// Numerator  = predict.estimate.prefix_tokens — the conversation prefix the
//              NEXT request will carry, which is exactly "context in use".
// Denominator = detail.context_budget_tokens — the only context-size number
//              the server actually reports. There is deliberately no model
//              context-window table consulted here: the closest server-side
//              number, cost pricing's `long_context_threshold`, is a BILLING
//              tier boundary (272k for GPT-5, 200k for Anthropic), not a
//              certified maximum, and dressing it up as a context window would
//              be exactly the fabricated-capability the honest-affordance
//              convention forbids.
//
// With no budget we still show the absolute prefix size, a real and useful
// observation, and say plainly that there is no ceiling to measure it against.
//
// The prefix is a FACT of the session and never depends on pricing: a model
// with no pricing entry (opencode alias ids such as "big-pickle") still
// reports its prefix, and this card must not restate that pricing gap as a
// data gap. Three honest states, in order:
//   1. no prefix number at all, and the sub-line says which of the two causes
//      applies (nothing observed yet vs. observed turns on an uncached
//      provider, distinguished by estimate.has_shape);
//   2. prefix known, ceiling unknown: show the token count and say the limit
//      for this model is not known;
//   3. prefix and budget known: show the percentage.
function ContextWindowCard({
  detail,
  predict,
  loading,
}: {
  detail: SessionDetail | null;
  predict?: PredictResponse | null;
  loading: boolean;
}) {
  const used = predict?.estimate?.prefix_tokens ?? 0;
  const observed = Boolean(predict?.estimate?.has_shape);
  const budget = detail?.context_budget_tokens ?? 0;
  const pct = budget > 0 && used > 0 ? Math.min(100, (used / budget) * 100) : null;

  if (used <= 0) {
    return (
      <HeroStat
        label="Context window used"
        value="n/a"
        loading={loading}
        sub={
          observed
            ? "Turns observed on this session, but none carried a cached prefix, so there is no context size to report."
            : "No prefix observed yet. The predictor needs at least one completed turn on this session."
        }
      />
    );
  }
  return (
    <HeroStat
      label="Context window used"
      value={pct != null ? pct.toFixed(0) : fmtCompact(used)}
      unit={pct != null ? "%" : "tokens"}
      variant={pct == null ? "accent" : pct > 90 ? "danger" : pct > 70 ? "warn" : "accent"}
      cornerPill={
        pct != null ? <Pill variant="neutral">{fmtCompact(budget)} budget</Pill> : undefined
      }
      sub={
        pct != null
          ? `${fmtCompact(used)} of ~${fmtCompact(budget)} carried into the next request`
          : `${fmtCompact(used)} tokens carried into the next request · the context limit for this model is not known, so there is no ceiling to measure against`
      }
    />
  );
}

// ── 2: % of limit spent ─────────────────────────────────────────────────────
//
// The subscription rate-limit gauge. Source is `limit.source`: "proxy" when it
// came from Anthropic's rate-limit response headers (so only sessions routed
// through the Observer proxy have it), or "transcript" when the tool's own
// session log carried it (codex token_count rate_limits).
//
// The unavailable case is a two-step ladder, not one flag, and each step has a
// DIFFERENT remedy — so each gets its own sentence rather than a shared
// "unavailable":
//   needs_proxy — no snapshot at all; routing this tool through the proxy
//                 would produce one.
//   no_window   — a snapshot exists but this account/provider never carries a
//                 subscription window (an Anthropic API key billed per token,
//                 OpenAI's per-minute-only headers). Nothing the operator does
//                 unlocks it, and saying "route through the proxy" would be a
//                 false instruction.
function LimitCard({
  limit,
  loading,
}: {
  limit?: PredictResponse["limit"];
  loading: boolean;
}) {
  const u5 = utilPct(limit?.window_5h_util);
  const u7 = utilPct(limit?.window_7d_util);
  const available = Boolean(limit?.available) && (u5 != null || u7 != null);

  if (!available) {
    return (
      <HeroStat
        label="% of limit spent"
        value="n/a"
        loading={loading}
        sub={
          limit?.no_window
            ? "This provider reports no subscription window - usage here is billed per token, so there is no limit to spend down."
            : limit?.needs_proxy
              ? "No rate-limit snapshot: route this tool through the Observer proxy and the gauge fills from the provider's own headers."
              : "No rate-limit snapshot for this session yet."
        }
      />
    );
  }
  // The headline is whichever window is closer to its ceiling — that is the one
  // that will actually stop the operator.
  const worst = Math.max(u5 ?? 0, u7 ?? 0);
  const parts: string[] = [];
  if (u5 != null) parts.push(`5h ${u5.toFixed(0)}%`);
  if (u7 != null) parts.push(`7d ${u7.toFixed(0)}%`);
  return (
    <HeroStat
      label="% of limit spent"
      value={worst.toFixed(0)}
      unit="%"
      variant={worst > 90 ? "danger" : worst > 70 ? "warn" : "accent"}
      cornerPill={limit?.source ? <Pill variant="neutral">{limit.source}</Pill> : undefined}
      sub={
        parts.join(" · ") +
        (limit?.observed_age ? ` · observed ${limit.observed_age} ago` : "")
      }
    />
  );
}

// ── 3: next-turn average cost ───────────────────────────────────────────────
//
// The predictor's MID band. The unit is a USER MESSAGE, which fans out to N
// model turns — so the fan-out and where it came from are surfaced on the tile
// rather than left implicit: only about a third of sessions carry the
// `user_prompt` boundaries that let the fan-out be OBSERVED, and a mid-band
// dollar figure resting on a static default is a different claim from one
// resting on this session's own history.
function NextTurnCostCard({
  predict,
  loading,
}: {
  predict?: PredictResponse | null;
  loading: boolean;
}) {
  const est = predict?.estimate;
  if (!est?.has_estimate) {
    return (
      <HeroStat
        label="Next-turn avg cost"
        value="n/a"
        loading={loading}
        sub={
          predict?.reason ||
          "Not enough history on this session yet - the predictor needs a completed turn with known pricing."
        }
      />
    );
  }
  const tier = est.turns_tier;
  const tierLabel =
    tier === "observed"
      ? "observed fan-out"
      : tier === "prior"
        ? "fan-out from a cross-session prior"
        : "fan-out from the static default";
  return (
    <HeroStat
      label="Next-turn avg cost"
      value={fmtUSD(est.mid.message_usd)}
      variant="accent"
      cornerPill={
        <Pill variant={tier === "observed" ? "success" : "warn"}>
          ×{est.mid.turns.toFixed(1)} turns
        </Pill>
      }
      sub={`${fmtUSD(est.low.message_usd)} – ${fmtUSD(est.high.message_usd)} per message · ${tierLabel}`}
    />
  );
}

// ── 4: process / network / memory ───────────────────────────────────────────
//
// The System tab's three headline facts, folded into one glance tile: how many
// processes were captured (and how many are still running), how much network
// the session generated, and the highest RSS any single process in the tree
// reached.
//
// PEAK RSS IS A MAX, NOT A SUM. Summing peak_rss_bytes across a process tree
// would add peaks that never coexisted and overstate memory by a large factor;
// the honest single number is the largest one process reached.
function SystemCard({
  procs,
  procsErr,
  network,
  networkErr,
  loading,
}: {
  procs?: SessionProcessResponse | null;
  procsErr: boolean;
  network?: SessionNetworkSummary | null;
  networkErr: boolean;
  loading: boolean;
}) {
  // Process capture is off entirely — a real, actionable state, and NOT the
  // same thing as "this session spawned nothing".
  if (procs && procs.diagnostics?.process_enabled === false) {
    return (
      <HeroStat
        label="Process · network · memory"
        value="off"
        sub="OS process capture is disabled - turn it on in Settings › Process to see the process tree, network and memory for this session."
      />
    );
  }
  if (!procs) {
    return (
      <HeroStat
        label="Process · network · memory"
        value="n/a"
        loading={loading}
        sub={
          procsErr
            ? "Process vitals could not be loaded - retrying."
            : "Loading process vitals…"
        }
      />
    );
  }

  const flat = flattenProcs(procs.roots);
  const running = flat.filter((n) => !n.exited).length;
  const peakRss = flat.reduce((m, n) => Math.max(m, n.peak_rss_bytes ?? 0), 0);
  const net = networkSummary(network);
  const bytes = net.request_bytes + net.response_bytes;

  // PROXIED API CALLS AND OS-OBSERVED CONNECTIONS ARE NOT THE SAME THING and are
  // never summed into one "network" count — the server discriminates them
  // (proxied flows carry body byte totals; raw sockets seen on the process tree
  // do not), and conflating them was the defect the ?summary=1 wire replaced.
  // Byte figures are suppressed when they measure zero: with body capture off a
  // proxied call reports no bytes, and "0 B" would read as an observed zero.
  const netLine = (() => {
    if (procs.diagnostics?.process_network_enabled === false) {
      return "network capture off";
    }
    if (networkErr) return "network summary unavailable";
    const parts: string[] = [];
    if (net.proxied_calls > 0) parts.push(`${fmtInt(net.proxied_calls)} API`);
    if (net.os_connections > 0) parts.push(`${fmtInt(net.os_connections)} conn`);
    if (parts.length === 0) return "no network captured";
    if (bytes > 0) parts.push(fmtBytes(bytes));
    return parts.join(" · ");
  })();

  return (
    <HeroStat
      label="Process · network · memory"
      value={fmtInt(procs.total)}
      unit={procs.total === 1 ? "process" : "processes"}
      cornerPill={
        running > 0 ? <Pill variant="success">{fmtInt(running)} live</Pill> : undefined
      }
      sub={
        <>
          {netLine}
          {" · "}
          {peakRss > 0 ? `peak RSS ${fmtBytes(peakRss)}` : "no memory samples"}
        </>
      }
    />
  );
}
