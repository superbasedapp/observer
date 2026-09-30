import { useState } from "react";
import { Button, ConfirmButton, Input, Pill, Table } from "@/components/primitives";
import { ApiError, fetchJSON } from "@/lib/api";
import { fmtDateTime, fmtInt } from "@/lib/format";
import { useApi } from "@/lib/useApi";
import {
  EMPTY_INPUTS,
  SINCE_PRESETS,
  applyBody,
  buildFilterBody,
  canApply,
  canRevert,
  deltaWord,
  filterProblem,
  fmtOldNew,
  fmtSignedUSD,
  inputsKey,
  planChangedFrom,
  planHeadline,
  runKindLabel,
  runStatus,
  serverErrorText,
  sinceForDays,
  skippedRows,
  windowLabel,
  type RepriceInputs,
  type RepricePlanView,
  type RepriceRunView,
  type RepriceStatusResponse,
} from "@/lib/reprice";

// RepriceCard - Settings -> Pricing "Re-price stored costs" (gap
// PRICE-REPRICE-1).
//
// Cost is stamped when a turn is captured. This card re-prices the stored
// rows at the price in force at each row's OWN time, through the daemon's
// /api/reprice/* routes (the Go side owns every rule: what is skipped, the
// compare-and-swap write, the run log, revert). The card only chooses a
// window, shows the dry run, and confirms.
//
// Low-friction, honest rules the card keeps:
//   - A dry run first; Apply is offered only for the exact inputs the shown
//     dry run was computed for, and it sends that dry run's digest back.
//   - If prices or rows moved since the dry run the server refuses (409
//     plan_changed) with a fresh plan; the card shows it and asks again.
//   - Apply and Revert are two-step (ConfirmButton), never window.confirm.
//   - A daemon without the routes (501, or 404 on an older build) gets a
//     muted line, not an error.

const STATUS = "/api/reprice/status";
const TH = "text-left font-semibold text-fg-3";
const NUM = "text-right font-mono tabular-nums";

type Notice = { tone: "info" | "success" | "warn"; text: string };

export function RepriceCard() {
  const res = useApi<RepriceStatusResponse>(STATUS);
  const token = res.data?.confirm_token ?? "";

  const [inputs, setInputs] = useState<RepriceInputs>(EMPTY_INPUTS);
  const [plan, setPlan] = useState<{ key: string; view: RepricePlanView } | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState<"plan" | "apply" | number | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const key = inputsKey(inputs);
  const problem = filterProblem(inputs);
  const applyable = canApply(plan?.view ?? null, plan?.key ?? null, key);
  const planStale = plan !== null && plan.key !== key;

  if (res.error) {
    const status = res.error instanceof ApiError ? res.error.status : 0;
    if (status === 501 || status === 404) {
      return (
        <Shell>
          <p className="text-[11px] text-fg-3">
            Re-pricing stored costs is not available in this daemon build.
          </p>
        </Shell>
      );
    }
    return (
      <Shell badge={<Pill variant="neutral">unavailable</Pill>}>
        <p className="text-[11px] text-fg-3">
          Re-pricing is managed from this machine only (it rewrites stored cost rows).{" "}
          {res.error.message}
        </p>
      </Shell>
    );
  }
  if (!res.data) return null;
  const st = res.data;
  const runs = st.runs ?? [];

  function set(field: keyof RepriceInputs, value: string) {
    setInputs((prev) => ({ ...prev, [field]: value }));
    setNotice(null);
  }

  async function post<T>(path: string, body: unknown): Promise<T> {
    return fetchJSON<T>(path, undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
      body: JSON.stringify(body),
    });
  }

  async function run(tag: "plan" | "apply" | number, fn: () => Promise<void>) {
    if (busy !== null) return;
    setBusy(tag);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof ApiError ? serverErrorText(e.body) || e.message : e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  const doPlan = () =>
    run("plan", async () => {
      const view = await post<RepricePlanView>("/api/reprice/plan", buildFilterBody(inputs));
      setPlan({ key, view });
      setNotice(null);
    });

  const doApply = () =>
    run("apply", async () => {
      if (!plan) return;
      try {
        const out = await post<RepriceRunView>("/api/reprice/apply", applyBody(plan.view));
        setPlan(null);
        setNotice({ tone: "success", text: appliedText(out) });
        res.reload();
      } catch (e) {
        const fresh = e instanceof ApiError ? planChangedFrom(e.status, e.body) : null;
        if (!fresh) throw e;
        setPlan({ key, view: fresh });
        setNotice({
          tone: "warn",
          text: "Prices or rows changed since the dry run, so nothing was written. The plan below is fresh - review it and apply again.",
        });
      }
    });

  const doRevert = (r: RepriceRunView) =>
    run(r.id, async () => {
      const out = await post<RepriceRunView>("/api/reprice/revert", { run_id: r.id });
      setNotice({ tone: "success", text: revertedText(r, out) });
      setPlan(null);
      res.reload();
    });

  return (
    <Shell>
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        Costs are stamped when a turn is captured, so a price change never reaches rows already
        stored. This re-prices stored rows at the price that was in force at each row&rsquo;s own
        time. Prices in force now: <span className="text-fg-1">{st.pricing.description}</span>.
      </p>
      <p className="text-[11px] leading-relaxed text-fg-3">
        Never changed: a cost the tool or vendor reported itself. A row with no known price stays
        unknown - it is never written as $0. Transcript rows stored without a cost are already
        priced when the dashboard reads them. Every apply is logged below and can be reverted.
      </p>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {SINCE_PRESETS.map((p) => (
            <Button
              key={p.label}
              size="sm"
              variant="ghost"
              disabled={busy !== null}
              onClick={() => {
                setInputs((prev) => ({ ...prev, since: sinceForDays(p.days, new Date()), until: "" }));
                setNotice(null);
              }}
            >
              {p.label}
            </Button>
          ))}
        </div>
        <div className="grid gap-2 sm:grid-cols-3">
          <Input
            label="Since"
            type="date"
            value={inputs.since}
            onChange={(e) => set("since", e.target.value)}
            disabled={busy !== null}
          />
          <Input
            label="Until"
            type="date"
            value={inputs.until}
            onChange={(e) => set("until", e.target.value)}
            disabled={busy !== null}
          />
          <Input
            label="Model"
            placeholder="all models"
            mono
            value={inputs.model}
            onChange={(e) => set("model", e.target.value)}
            disabled={busy !== null}
          />
        </div>
        <p className="text-[10.5px] text-fg-3">Empty dates mean no bound. Empty model means every model.</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="secondary"
          onClick={doPlan}
          disabled={busy !== null || problem !== null}
          loading={busy === "plan"}
          title={problem ?? "Compute what would change - writes nothing"}
        >
          Dry run
        </Button>
        <ConfirmButton
          size="sm"
          variant="soft"
          armedVariant="primary"
          timeoutMs={8000}
          onConfirm={() => void doApply()}
          disabled={busy !== null || !applyable}
          loading={busy === "apply"}
          title={applyable ? undefined : applyHint(plan?.view ?? null, planStale)}
          confirmLabel="Click again to apply"
          armedNote={
            plan
              ? `Rewrites ${fmtInt(plan.view.summary.changed)} stored cost${plan.view.summary.changed === 1 ? "" : "s"} (${fmtSignedUSD(plan.view.summary.delta_usd)}). Revertible from the history below.`
              : undefined
          }
        >
          Apply
        </ConfirmButton>
        {problem && <span className="text-[11.5px] text-warn">{problem}</span>}
        {err && <span className="text-[11.5px] text-danger">{err}</span>}
      </div>

      {notice && (
        <p
          role="status"
          className={
            notice.tone === "warn"
              ? "text-[11.5px] text-warn"
              : notice.tone === "success"
                ? "text-[11.5px] text-success"
                : "text-[11.5px] text-fg-2"
          }
        >
          {notice.text}
        </p>
      )}

      {plan && <PlanView view={plan.view} stale={planStale} />}

      <RunHistory runs={runs} busy={busy} onRevert={(r) => void doRevert(r)} />
    </Shell>
  );
}

function applyHint(plan: RepricePlanView | null, stale: boolean): string {
  if (!plan) return "Run a dry run first";
  if (stale) return "The inputs changed since the dry run - run it again";
  return "Nothing to change";
}

function appliedText(r: RepriceRunView): string {
  const filled = r.filled > 0 ? ` (${fmtInt(r.filled)} had no cost before)` : "";
  const missed =
    r.cas_missed > 0
      ? ` ${fmtInt(r.cas_missed)} row${r.cas_missed === 1 ? " was" : "s were"} rewritten by capture in the meantime and left as captured.`
      : "";
  return `Run #${r.id}: re-priced ${fmtInt(r.changed)} row${r.changed === 1 ? "" : "s"}${filled}, stored total ${fmtOldNew(r.old_usd, r.new_usd)} (${fmtSignedUSD(r.delta_usd)}).${missed}`;
}

function revertedText(target: RepriceRunView, r: RepriceRunView): string {
  const skipped =
    target.changed > r.changed
      ? ` ${fmtInt(target.changed - r.changed)} row${target.changed - r.changed === 1 ? " was" : "s were"} changed since and left alone.`
      : "";
  return `Run #${r.id}: reverted run #${target.id}, restored ${fmtInt(r.changed)} row${r.changed === 1 ? "" : "s"} (${fmtSignedUSD(r.delta_usd)}).${skipped}`;
}

function PlanView({ view, stale }: { view: RepricePlanView; stale: boolean }) {
  const s = view.summary;
  const tables = s.tables ?? [];
  const models = s.models ?? [];
  const skipped = skippedRows(s.skipped);
  return (
    <div className={`space-y-3 rounded-2 border border-line-2 bg-bg-3/40 p-3 text-[11.5px] ${stale ? "opacity-60" : ""}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="font-semibold text-fg-1">Dry run - nothing written yet</div>
        <div className="text-[10.5px] text-fg-3">
          {windowLabel(view.since, view.until)}
          {view.model ? ` - ${view.model}` : " - all models"} - priced with {view.pricing.description}
        </div>
      </div>
      {stale && (
        <p className="text-[11px] text-warn">The inputs changed since this dry run. Run it again to apply.</p>
      )}
      <div className="text-fg-1">{planHeadline(s)}</div>
      {s.changed > 0 && (
        <div className="text-fg-2">
          Stored total <span className="font-mono">{fmtOldNew(s.old_usd, s.new_usd)}</span>{" "}
          <span className="font-mono text-fg-1">({fmtSignedUSD(s.delta_usd)})</span>, {deltaWord(s.delta_usd)}.
        </div>
      )}

      {tables.length > 0 && (
        <Table
          size="sm"
          padded
          minWidth={420}
          head={
            <tr>
              <th className={TH}>Stored in</th>
              <th className={`${TH} text-right`}>Scanned</th>
              <th className={`${TH} text-right`}>Changes</th>
              <th className={`${TH} text-right`}>Old -&gt; new</th>
              <th className={`${TH} text-right`}>Delta</th>
            </tr>
          }
        >
          {tables.map((t) => (
            <tr key={t.table}>
              <td className="font-mono">{t.table}</td>
              <td className={NUM}>{fmtInt(t.scanned)}</td>
              <td className={NUM}>{fmtInt(t.changed)}</td>
              <td className={NUM}>{fmtOldNew(t.old_usd, t.new_usd)}</td>
              <td className={NUM}>{fmtSignedUSD(t.new_usd - t.old_usd)}</td>
            </tr>
          ))}
        </Table>
      )}

      {models.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Top models by change
          </div>
          <Table
            size="sm"
            padded
            minWidth={420}
            maxHeight={260}
            stickyHead
            head={
              <tr>
                <th className={TH}>Model</th>
                <th className={`${TH} text-right`}>Changes</th>
                <th className={`${TH} text-right`}>Old -&gt; new</th>
                <th className={`${TH} text-right`}>Delta</th>
              </tr>
            }
          >
            {models.map((m) => (
              <tr key={m.model}>
                <td className="font-mono">{m.model || "(none)"}</td>
                <td className={NUM}>{fmtInt(m.changed)}</td>
                <td className={NUM}>{fmtOldNew(m.old_usd, m.new_usd)}</td>
                <td className={NUM}>{fmtSignedUSD(m.new_usd - m.old_usd)}</td>
              </tr>
            ))}
          </Table>
        </div>
      )}

      {skipped.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Left as they are</div>
          <ul className="space-y-0.5 text-fg-2">
            {skipped.map((r) => (
              <li key={r.reason} className="flex justify-between gap-3">
                <span>{r.label}</span>
                <span className="font-mono tabular-nums text-fg-3">{fmtInt(r.count)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {view.org?.enrolled && view.org.note && <p className="text-[11px] text-fg-3">{view.org.note}</p>}
    </div>
  );
}

function RunHistory({
  runs,
  busy,
  onRevert,
}: {
  runs: RepriceRunView[];
  busy: "plan" | "apply" | number | null;
  onRevert: (r: RepriceRunView) => void;
}) {
  return (
    <div className="space-y-1">
      <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">History</div>
      {runs.length === 0 ? (
        <p className="text-[11px] text-fg-3">No re-price runs yet. Stored costs are as captured.</p>
      ) : (
        <Table
          size="sm"
          padded
          minWidth={640}
          head={
            <tr>
              <th className={TH}>When</th>
              <th className={TH}>Run</th>
              <th className={TH}>Window</th>
              <th className={TH}>Model</th>
              <th className={`${TH} text-right`}>Changed</th>
              <th className={`${TH} text-right`}>Delta</th>
              <th className={TH}>Status</th>
              <th className={TH} aria-label="Actions" />
            </tr>
          }
        >
          {runs.map((r) => {
            const s = runStatus(r);
            return (
              <tr key={r.id}>
                <td className="whitespace-nowrap">{fmtDateTime(r.created_at)}</td>
                <td className="whitespace-nowrap">
                  #{r.id} {runKindLabel(r)}
                </td>
                <td className="whitespace-nowrap">{windowLabel(r.since, r.until)}</td>
                <td className="font-mono">{r.model || "all"}</td>
                <td className={NUM}>{fmtInt(r.changed)}</td>
                <td className={NUM}>{fmtSignedUSD(r.delta_usd)}</td>
                <td>
                  <Pill variant={s.tone}>{s.text}</Pill>
                </td>
                <td className="text-right">
                  {canRevert(r) && (
                    <ConfirmButton
                      size="sm"
                      variant="secondary"
                      armedVariant="danger"
                      timeoutMs={8000}
                      onConfirm={() => onRevert(r)}
                      disabled={busy !== null}
                      loading={busy === r.id}
                      confirmLabel="Click again to revert"
                      armedNote="Restores the costs this run replaced. Rows changed since are left alone."
                    >
                      Revert
                    </ConfirmButton>
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      )}
    </div>
  );
}

function Shell({ badge, children }: { badge?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="mt-6 space-y-3 rounded-3 border border-line-2 bg-bg-2 p-4">
      <header className="flex items-baseline justify-between gap-3">
        <h4 className="text-[13px] font-semibold text-fg-0">Re-price stored costs</h4>
        {badge}
      </header>
      {children}
    </section>
  );
}
