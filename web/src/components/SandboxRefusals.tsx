// SandboxRefusals is the Terminals page's view of the sandbox egress refusal
// audit (OpenShell build plan 05, section 3.1 and 3.5, lanes N1 and N5): the
// hosts a sandboxed agent run tried to reach and the gateway refused, newest
// first, read from GET /api/sandbox/refusals (owner-local). The rows are
// written by the daemon, never from here.
//
// On a refusal the server's advisor table marks offerable (only an
// allow-list miss, never a provider host, a private range, a host-local or
// SSRF-floor refusal, never a host the organization's pin leaves out), the
// card offers "Allow this host". Applying it is one PUT of one refusal id to
// /api/sandbox/refusals/allow through the config save preview, so the
// owner sees the change and clicks Save; there is no batch form and nothing
// is applied on its own (ruling R-8).

import { useState } from "react";
import { ChartShell, EmptyState, InlineLoading, SuccessCheck, Table, Tooltip } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { ConfigSaveCancelled, saveConfigEdit } from "@/lib/configSectionSave";
import { fmtClock, fmtShortId } from "@/lib/format";

/** One stored refusal (internal/store.SandboxEgressRefusal). */
export type SandboxRefusal = {
  id: number;
  run_id: string;
  project_root: string;
  backend: string;
  tier: string;
  host: string;
  port: number;
  rule: string;
  key: string;
  at: string;
};

/** The page GET /api/sandbox/refusals answers. */
export type SandboxRefusalsPage = {
  refusals: SandboxRefusal[];
  next_before?: number;
  /** Per run id, refusals dropped before they could be written (a bound was
   *  reached; lane OC, ledger OSH-34). Absent when none was dropped. */
  dropped?: Record<string, number>;
  /** Per run id, refusals that may be the run's: dropped while its box id
   *  was not recorded yet, counted against every run waiting then, so it
   *  can over-count and is never read as zero (lane OC). */
  uncertain?: Record<string, number>;
  /** Per run id, the part of its dropped count that could not be sent to
   *  Observer (the run's link down or busy; tracker F-012). Absent when
   *  none. */
  link_lost?: Record<string, number>;
  /** Per run id, new requests refused while the run's link to Observer was
   *  down, under the organization's "Require
   *  refusal audit" (tracker F-012). Absent when none was closed. */
  egress_closed?: Record<string, number>;
  /** Per run id, its oldest rows removed to keep the run under the per-run
   *  total bound (tracker F-009). Absent when none was removed. */
  evicted?: Record<string, number>;
};

/** One run whose refusal rows are incomplete, or whose link was lost. */
export type IncompleteRun = {
  runId: string;
  dropped: number;
  uncertain: number;
  linkLost: number;
  egressClosed: number;
  evicted: number;
};

/**
 * incompleteRuns lists every run the answer says is incomplete: a run with
 * a dropped or an uncertain count above zero is never read as complete,
 * however whole its rows look. A run absent from both maps dropped none.
 * Sorted by run id, so the lines do not move between loads.
 */
export function incompleteRuns(
  page: Pick<SandboxRefusalsPage, "dropped" | "uncertain" | "link_lost" | "egress_closed" | "evicted"> | null | undefined,
): IncompleteRun[] {
  const out = new Map<string, IncompleteRun>();
  const add = (m: Record<string, number> | undefined, key: "dropped" | "uncertain" | "linkLost" | "egressClosed" | "evicted") => {
    for (const [runId, n] of Object.entries(m ?? {})) {
      if (!(n > 0)) continue;
      const cur = out.get(runId) ?? { runId, dropped: 0, uncertain: 0, linkLost: 0, egressClosed: 0, evicted: 0 };
      cur[key] = n;
      out.set(runId, cur);
    }
  };
  add(page?.dropped, "dropped");
  add(page?.uncertain, "uncertain");
  add(page?.link_lost, "linkLost");
  add(page?.egress_closed, "egressClosed");
  add(page?.evicted, "evicted");
  return [...out.values()].sort((a, b) => (a.runId < b.runId ? -1 : a.runId > b.runId ? 1 : 0));
}

/** droppedLine is the card line for a run's dropped count. */
export function droppedLine(n: number): string {
  return `${n} refused connection${n === 1 ? " of this run was" : "s of this run were"} not recorded (a bound was reached); the rows below are incomplete.`;
}

/** uncertainLine is the card line for a run's uncertain count. */
export function uncertainLine(n: number): string {
  return `Up to ${n} more refused connection${n === 1 ? "" : "s"} may belong to this run (recorded while its sandbox was starting under a flood of unattributed events).`;
}

/** linkLostLine is the card line for the part of a run's dropped count lost
 *  while its link to Observer was down. */
export function linkLostLine(n: number): string {
  return `${n} of them could not be sent to Observer (link down or busy).`;
}

/** egressClosedLine is the card line for a run's requests refused while its
 *  egress was closed for a lost link. */
export function egressClosedLine(n: number): string {
  return `${n} request${n === 1 ? " was" : "s were"} refused because this run's link to Observer was down and your organization requires the refusal audit; new connections are refused until the link is back, so nothing left.`;
}

/** evictedLine is the card line for a run's rows removed past the per-run
 *  total bound. */
export function evictedLine(n: number): string {
  return `The ${n} oldest refused connection${n === 1 ? " of this run was" : "s of this run were"} removed to keep the run under its row limit; the rows below are the newest.`;
}

/** IncompleteRunsNotice renders one block per incomplete run (pure). */
export function IncompleteRunsNotice({ runs }: { runs: IncompleteRun[] }) {
  if (runs.length === 0) return null;
  return (
    <div className="space-y-1 rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-[11px] text-fg-2" role="status" data-incomplete-runs={runs.length}>
      {runs.map((r) => (
        <div key={r.runId} data-incomplete-run={r.runId}>
          <span className="font-mono text-fg-1">Run {fmtShortId(r.runId, 10)}</span>
          <span className="ml-1 rounded-1 border border-warn/50 px-1 text-[10px] text-warn">
            {r.dropped > 0 || r.uncertain > 0 || r.evicted > 0 ? "incomplete" : "link lost"}
          </span>
          {r.dropped > 0 && <span className="block">{droppedLine(r.dropped)}</span>}
          {r.linkLost > 0 && <span className="block">{linkLostLine(r.linkLost)}</span>}
          {r.uncertain > 0 && <span className="block">{uncertainLine(r.uncertain)}</span>}
          {r.egressClosed > 0 && <span className="block">{egressClosedLine(r.egressClosed)}</span>}
          {r.evicted > 0 && <span className="block">{evictedLine(r.evicted)}</span>}
        </div>
      ))}
    </div>
  );
}

// refusalRuleLabels names each rule of the closed vocabulary
// (internal/sandboxnet/refusal.go) in plain words. A rule this build does not
// know shows its own name.
const refusalRuleLabels: Record<string, string> = {
  "allow-list-miss": "Not on the host allow-list",
  "private-range": "Private address range",
  "provider-host": "Model provider host",
  "host-local": "This computer's own address",
  "tier-none": "This run has no network",
  "ssrf-floor": "An address no allow-list can open",
  "literal-ip": "An IP address instead of a host name",
  "port-not-allowed": "Port not allowed",
  "tls-server-name": "TLS server name missing or different",
};

/** refusalRuleLabel is the plain-words name of a refusal rule. */
export function refusalRuleLabel(rule: string): string {
  return refusalRuleLabels[rule] ?? rule;
}

/** hostPort renders a refused target as host:port (IPv6 in brackets). */
export function hostPort(host: string, port: number): string {
  const h = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return port > 0 ? `${h}:${port}` : h;
}

/** One refusal's offer (GET /api/sandbox/refusals/allow). */
export type SandboxRefusalOffer = {
  refusal_id: number;
  host: string;
  offerable: boolean;
  reason: string;
  message?: string;
  /** The server's capability flag (tracker F-013): the refusal's rule is
   *  one the owner's host list could lift, so a not-offered answer is worth
   *  showing with its message. The card branches on this, never on a rule
   *  name. */
  explain?: boolean;
};

/** The GET /api/sandbox/refusals/allow answer. */
export type SandboxRefusalOffersPage = {
  confirm_token: string;
  config_writable: boolean;
  scope: string;
  scope_label: string;
  key: string;
  offers: SandboxRefusalOffer[];
};

export type SandboxRefusalsViewProps = {
  rows: SandboxRefusal[];
  /** Offers keyed by refusal id; a row with none is offered nothing. */
  offers?: Map<number, SandboxRefusalOffer>;
  /** What an applied offer covers, in plain words. */
  scopeLabel?: string;
  /** The refusal whose offer is being applied. */
  busyId?: number | null;
  onAllow?: (offer: SandboxRefusalOffer) => void;
};

/** allowScopeNote is the line under the table saying what an allow covers. */
export function allowScopeNote(scopeLabel: string): string {
  return `Allowing a host adds it to the sandbox host allow-list for ${scopeLabel}. There is no per-project list, so it is not limited to the run's project. Runs already open keep their list.`;
}

/** SandboxRefusalsView renders the refusal rows (pure, for the tests). */
export function SandboxRefusalsView({ rows, offers, scopeLabel, busyId, onAllow }: SandboxRefusalsViewProps) {
  if (rows.length === 0) {
    return (
      <EmptyState
        variant="inline"
        illustration="sessions"
        illustrationSize={96}
        title="No refused connections"
        body="When a sandboxed run tries to reach a host its network rules do not allow, the attempt is listed here."
      />
    );
  }
  return (
    <Table
      maxHeight={320}
      stickyHead
      size="sm"
      minWidth={640}
      tableClassName="font-mono"
      head={
        <tr>
          <th className="py-1 pr-2 font-medium">When</th>
          <th className="py-1 pr-2 font-medium">Run</th>
          <th className="py-1 pr-2 font-medium">Host</th>
          <th className="py-1 pr-2 font-medium">Why</th>
          <th className="py-1 pr-2 font-medium">Decided by</th>
          <th className="py-1 font-medium">Action</th>
        </tr>
      }
    >
      {rows.map((r) => (
        <tr key={r.id} className="border-t border-line-1 text-fg-2" data-refusal-id={r.id}>
          <td className="whitespace-nowrap py-1 pr-2">{fmtClock(r.at)}</td>
          <td className="py-1 pr-2">
            <Tooltip content={`${r.run_id} · ${r.backend || "unknown backend"} · ${r.tier || "unknown tier"}`}>
              <span tabIndex={0} className="cursor-help focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring">
                {fmtShortId(r.run_id, 10)}
              </span>
            </Tooltip>
          </td>
          <td className="break-all py-1 pr-2">{hostPort(r.host, r.port)}</td>
          <td className="py-1 pr-2 font-sans">{refusalRuleLabel(r.rule)}</td>
          <td className="py-1 pr-2 text-fg-3">{r.key || "-"}</td>
          <td className="py-1 font-sans">
            <OfferCell offer={offers?.get(r.id)} scopeLabel={scopeLabel} busy={busyId === r.id} onAllow={onAllow} />
          </td>
        </tr>
      ))}
    </Table>
  );
}

// OfferCell is one row's action: the allow button on an offerable refusal,
// the reason it is not offered when the server says the answer explains
// itself (offer.explain: a rule the host list could lift), and nothing
// otherwise (a rule no host list lifts is never offered).
function OfferCell({
  offer,
  scopeLabel,
  busy,
  onAllow,
}: {
  offer?: SandboxRefusalOffer;
  scopeLabel?: string;
  busy: boolean;
  onAllow?: (offer: SandboxRefusalOffer) => void;
}) {
  if (offer?.offerable && onAllow) {
    return (
      <button
        type="button"
        disabled={busy}
        onClick={() => onAllow(offer)}
        title={scopeLabel ? `Adds ${offer.host} for ${scopeLabel}` : undefined}
        className="rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-[11px] text-accent hover:bg-accent/25 disabled:opacity-50"
      >
        {busy ? "saving..." : "Allow this host"}
      </button>
    );
  }
  if (offer && !offer.offerable && offer.explain && offer.message) {
    return <span className="text-fg-3">{offer.message}</span>;
  }
  return <span className="text-fg-3">-</span>;
}

/**
 * SandboxRefusalsCard is the Terminals page card: the newest refusals, one
 * page at a time ("Show older" follows the route's next_before cursor), and
 * the advisor's offer on each.
 */
export function SandboxRefusalsCard() {
  const [before, setBefore] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const params = before ? { before: String(before) } : undefined;
  const page = useApi<SandboxRefusalsPage>("/api/sandbox/refusals", params, [before]);
  const offersPage = useApi<SandboxRefusalOffersPage>("/api/sandbox/refusals/allow", params, [before]);
  const rows = page.data?.refusals ?? [];
  const offers = new Map((offersPage.data?.offers ?? []).map((o) => [o.refusal_id, o]));
  const scopeLabel = offersPage.data?.scope_label;

  const allow = async (offer: SandboxRefusalOffer) => {
    const tok = offersPage.data?.confirm_token;
    if (!tok) return;
    setBusyId(offer.refusal_id);
    setMsg(null);
    setErr(null);
    try {
      await saveConfigEdit(
        "/api/sandbox/refusals/allow",
        "terminal.sandbox",
        { refusal_id: offer.refusal_id },
        { "X-Observer-Confirm": tok },
        { title: `Allow ${offer.host} for ${scopeLabel ?? "sandboxed runs"}` },
      );
      setMsg(`Allowed ${offer.host}. Sandboxed runs started from now on can reach it.`);
      offersPage.reload();
    } catch (e) {
      if (!(e instanceof ConfigSaveCancelled)) setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <ChartShell
      title="Refused connections"
      sub="Hosts a sandboxed agent run tried to reach that its network rules refused, newest first. Recorded on this computer only."
    >
      <div className="space-y-2 p-1 text-[11px]">
        {page.loading && !page.data ? (
          <InlineLoading label="Loading refused connections" block />
        ) : page.error ? (
          <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
            Could not read the refused connections: {page.error.message}
          </div>
        ) : (
          <>
            <IncompleteRunsNotice runs={incompleteRuns(page.data)} />
            <SandboxRefusalsView rows={rows} offers={offers} scopeLabel={scopeLabel} busyId={busyId} onAllow={allow} />
          </>
        )}
        {scopeLabel && rows.length > 0 && <p className="text-[11px] text-fg-3">{allowScopeNote(scopeLabel)}</p>}
        {err && (
          <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{err}</div>
        )}
        {msg && <SuccessCheck label={msg} className="!text-[11px]" />}
        <div className="flex items-center gap-3">
          {before !== null && (
            <button type="button" onClick={() => setBefore(null)} className="text-[11px] text-accent hover:underline">
              Newest
            </button>
          )}
          {page.data?.next_before ? (
            <button
              type="button"
              onClick={() => setBefore(page.data?.next_before ?? null)}
              className="text-[11px] text-accent hover:underline"
            >
              Show older
            </button>
          ) : null}
        </div>
      </div>
    </ChartShell>
  );
}
