import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { ChartShell, Pill, Tooltip } from "@/components/primitives";
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
  "rounded-2 border border-line-2 bg-bg-3 px-2.5 py-1 text-caption text-fg-1 hover:border-line-3 hover:text-fg-0 disabled:opacity-50";

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

// BLOCK_COLUMNS are the four read-only columns both lists share. The
// newest-first order from latestPerScope is the initial order; a header
// click re-sorts (Blocked sorts by the raw timestamp, not the label).
const BLOCK_COLUMNS: ColumnDef<OverrideEvent, unknown>[] = [
  {
    id: "rule",
    header: "Rule",
    accessorKey: "rule_id",
    cell: ({ row }) => <span className="font-mono text-fg-1">{row.original.rule_id}</span>,
  },
  {
    id: "tool",
    header: "Tool",
    accessorFn: (ev) => ev.tool ?? "",
    cell: ({ row }) => <span className="text-fg-2">{row.original.tool || "-"}</span>,
  },
  {
    id: "session",
    header: "Session",
    accessorFn: (ev) => ev.session_id ?? "",
    cell: ({ row }) => (
      <span
        className="block max-w-[160px] truncate font-mono text-[10.5px] text-fg-3"
        title={row.original.session_id}
      >
        {row.original.session_id ? fmtShortId(row.original.session_id, 8) : "-"}
      </span>
    ),
  },
  {
    id: "blocked",
    header: "Blocked",
    accessorFn: (ev) => new Date(ev.ts).getTime(),
    cell: ({ row }) => (
      <span className="whitespace-nowrap text-fg-3">{fmtDateTime(row.original.ts)}</span>
    ),
  },
];

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

  // Rebuilt per render on purpose: the action cell reads busy, covered
  // and allowForSession, all of which change with this component's state.
  const overridableColumns: ColumnDef<OverrideEvent, unknown>[] = [
    ...BLOCK_COLUMNS,
    {
      id: "action",
      header: "",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => {
        const ev = row.original;
        const already = covered.has(scopeKey(ev.rule_id, ev.session_id));
        if (already) return <Pill variant="neutral">allowed</Pill>;
        if (!ev.session_id) {
          // No session id means nothing to scope a grant to - the same
          // honesty the deny text carries on that lane. Never offer a
          // button the daemon would refuse.
          return (
            <Tooltip content="This block arrived with no session id, so an override cannot be scoped to it. Re-run the request through a session-identified client, or ask your admin.">
              <span
                tabIndex={0}
                className="cursor-help text-caption text-fg-3 underline decoration-dotted underline-offset-[3px] focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                not scopable
              </span>
            </Tooltip>
          );
        }
        return (
          <Tooltip
            content={`Grant a ${blockedTTLHours}h approval scoped to this session - the same grant as: observer guard approve ${ev.rule_id} --session <id>`}
          >
            <button
              type="button"
              className={actionBtn}
              disabled={busy === ev.id}
              onClick={() => allowForSession(ev)}
            >
              {busy === ev.id ? "Allowing..." : "Allow for this session"}
            </button>
          </Tooltip>
        );
      },
    },
  ];

  if (overridable.length === 0 && locked.length === 0) return null;

  return (
    <ChartShell
      title="Organization guardrails"
      right={<Pill variant="neutral">org policy bundle active</Pill>}
      sub={
        <>
          Your organization publishes the guardrail floor for this machine. It can mark a rule
          overridable, which lets you take one blocked action yourself with a scoped, time-boxed and
          audited grant. Every override you exercise is reported back to your organization.
        </>
      }
    >

      {err && <div className="mb-3 text-[11.5px] text-danger">{err}</div>}

      {overridable.length > 0 && (
        <div className="mb-4">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
            Blocked - override available
          </div>
          <DataTable<OverrideEvent>
            data={overridable}
            columns={overridableColumns}
            rowKey={(ev) => String(ev.id)}
            minWidth={560}
          />
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
          <DataTable<OverrideEvent>
            data={locked}
            columns={BLOCK_COLUMNS}
            rowKey={(ev) => String(ev.id)}
            minWidth={420}
          />
        </div>
      )}
    </ChartShell>
  );
}
