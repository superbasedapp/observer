import { useMemo, useState } from "react";
import { Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fetchJSON, apiReason } from "@/lib/api";
import { fmtDateTime, fmtShortId } from "@/lib/format";

// Org-granted override, node-dashboard surface (Track B of the org
// guardrail control wave).
//
// Two lists, one card:
//   - "Blocked - override available": enforced denies of rules the
//     organization marked overridable, each with a one-click
//     "Allow for this session" that creates the SCOPED, time-boxed
//     approval the CLI's `observer guard approve --session` creates.
//   - "Blocked by org policy": read-only. These cannot be overridden
//     on this node at all, so the card says so instead of offering a
//     button the daemon would refuse.
//
// The whole card HIDES when neither list has a row, which is always
// the case on a node with no org policy bundle - the Security page
// renders exactly as it did before the wave.

type OverrideEvent = {
  id: number;
  ts: string;
  session_id?: string;
  tool?: string;
  rule_id: string;
  decision?: string;
  enforced: boolean;
  reason?: string;
  overridable?: boolean;
  org_locked?: boolean;
};

type OverrideEventsResponse = { events: OverrideEvent[] | null; count: number };

type ApprovalRow = { id: number; rule_id: string; scope: string; session_id?: string };
type ApprovalsResponse = { approvals: ApprovalRow[] | null };

// blockedTTLHours is the lifetime of an approval granted from this
// card. It matches `observer guard approve`'s own --ttl default, so
// the button and the CLI grant the same thing.
const blockedTTLHours = 24;

const actionBtn =
  "rounded-2 border border-line-1 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-1 hover:border-line-2 hover:text-fg-0 disabled:opacity-50";

// scopeKey identifies one (rule, session) pair for dedup and for the
// already-granted check. The separator cannot occur in either half.
function scopeKey(ruleID: string, sessionID: string | undefined): string {
  return `${ruleID} :: ${sessionID ?? ""}`;
}

// latestPerScope keeps the most recent event per (rule, session) so a
// retry loop does not fill the card with one repeated block.
function latestPerScope(rows: OverrideEvent[]): OverrideEvent[] {
  const seen = new Map<string, OverrideEvent>();
  for (const ev of rows) {
    const key = scopeKey(ev.rule_id, ev.session_id);
    const prev = seen.get(key);
    if (!prev || new Date(ev.ts).getTime() > new Date(prev.ts).getTime()) seen.set(key, ev);
  }
  return [...seen.values()].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
}

export function GuardOverrideCard() {
  const events = useApi<OverrideEventsResponse>("/api/guard/events", {
    hours: 168,
    decision: "deny",
    limit: 200,
  });
  const approvals = useApi<ApprovalsResponse>("/api/guard/approvals");
  const [busy, setBusy] = useState(0);
  const [err, setErr] = useState("");

  const rows = events.data?.events ?? [];
  const overridable = useMemo(
    () => latestPerScope(rows.filter((e) => e.enforced && e.overridable)).slice(0, 8),
    [rows],
  );
  const locked = useMemo(
    () => latestPerScope(rows.filter((e) => e.enforced && e.org_locked)).slice(0, 8),
    [rows],
  );

  // A grant already covering (rule, session) - the button must not
  // create a duplicate row in the exception register.
  const covered = useMemo(() => {
    const s = new Set<string>();
    for (const a of approvals.data?.approvals ?? []) {
      if (a.scope === "session") s.add(scopeKey(a.rule_id, a.session_id));
    }
    return s;
  }, [approvals.data]);

  const allowForSession = async (ev: OverrideEvent) => {
    if (!ev.session_id) return;
    setBusy(ev.id);
    setErr("");
    try {
      await fetchJSON("/api/guard/approvals", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_id: ev.rule_id,
          scope: "session",
          session_id: ev.session_id,
          ttl_hours: blockedTTLHours,
        }),
      });
      approvals.reload();
      events.reload();
    } catch (e: unknown) {
      setErr(apiReason(e));
    } finally {
      setBusy(0);
    }
  };

  if (overridable.length === 0 && locked.length === 0) return null;

  return (
    <section className="rounded-3 border border-line-1 bg-bg-1 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[13px] font-semibold text-fg-0">Organization guardrails</h2>
        <Pill variant="neutral">org policy bundle active</Pill>
      </div>
      <p className="mb-3 max-w-2xl text-[11.5px] leading-snug text-fg-3">
        Your organization publishes the guardrail floor for this machine. It can mark a rule
        overridable, which lets you take one blocked action yourself with a scoped, time-boxed and
        audited grant. Every override you exercise is reported back to your organization.
      </p>

      {err && <div className="mb-3 text-[11.5px] text-danger">{err}</div>}

      {overridable.length > 0 && (
        <div className="mb-4">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
            Blocked - override available
          </div>
          <table className="w-full text-left text-[11.5px]">
            <thead>
              <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                <th className="py-1 pr-3 font-semibold">Rule</th>
                <th className="py-1 pr-3 font-semibold">Tool</th>
                <th className="py-1 pr-3 font-semibold">Session</th>
                <th className="py-1 pr-3 font-semibold">Blocked</th>
                <th className="py-1 font-semibold"></th>
              </tr>
            </thead>
            <tbody>
              {overridable.map((ev) => {
                const already = covered.has(scopeKey(ev.rule_id, ev.session_id));
                return (
                  <tr key={ev.id} className="border-b border-line-1/60">
                    <td className="py-1.5 pr-3 font-mono text-fg-1">{ev.rule_id}</td>
                    <td className="py-1.5 pr-3 text-fg-2">{ev.tool || "-"}</td>
                    <td
                      className="max-w-[160px] truncate py-1.5 pr-3 font-mono text-[10.5px] text-fg-3"
                      title={ev.session_id}
                    >
                      {ev.session_id ? fmtShortId(ev.session_id, 8) : "-"}
                    </td>
                    <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">{fmtDateTime(ev.ts)}</td>
                    <td className="py-1.5 text-right">
                      {already ? (
                        <Pill variant="neutral">allowed</Pill>
                      ) : !ev.session_id ? (
                        // No session id means nothing to scope a grant
                        // to - the same honesty the deny text carries
                        // on that lane. Never offer a button the
                        // daemon would refuse.
                        <span
                          className="text-[11px] text-fg-3"
                          title="This block arrived with no session id, so an override cannot be scoped to it. Re-run the request through a session-identified client, or ask your admin."
                        >
                          not scopable
                        </span>
                      ) : (
                        <button
                          type="button"
                          className={actionBtn}
                          disabled={busy === ev.id}
                          onClick={() => allowForSession(ev)}
                          title={`Grant a ${blockedTTLHours}h approval scoped to this session - the same grant as: observer guard approve ${ev.rule_id} --session <id>`}
                        >
                          {busy === ev.id ? "Allowing..." : "Allow for this session"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {locked.length > 0 && (
        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
            Blocked by org policy
          </div>
          <p className="mb-1.5 text-[11px] text-fg-3">
            These rules are locked by your organization. A local approval is refused, and an
            existing one is ignored - ask your admin to mark the rule overridable.
          </p>
          <table className="w-full text-left text-[11.5px]">
            <thead>
              <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                <th className="py-1 pr-3 font-semibold">Rule</th>
                <th className="py-1 pr-3 font-semibold">Tool</th>
                <th className="py-1 pr-3 font-semibold">Session</th>
                <th className="py-1 font-semibold">Blocked</th>
              </tr>
            </thead>
            <tbody>
              {locked.map((ev) => (
                <tr key={ev.id} className="border-b border-line-1/60">
                  <td className="py-1.5 pr-3 font-mono text-fg-1">{ev.rule_id}</td>
                  <td className="py-1.5 pr-3 text-fg-2">{ev.tool || "-"}</td>
                  <td
                    className="max-w-[160px] truncate py-1.5 pr-3 font-mono text-[10.5px] text-fg-3"
                    title={ev.session_id}
                  >
                    {ev.session_id ? fmtShortId(ev.session_id, 8) : "-"}
                  </td>
                  <td className="whitespace-nowrap py-1.5 text-fg-3">{fmtDateTime(ev.ts)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
