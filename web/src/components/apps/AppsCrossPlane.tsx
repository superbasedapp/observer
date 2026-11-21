// Your apps > Analytics, "Built on this machine" (Plane A W4-3/W5-8, lane C3;
// GET /api/obs/services/coding, contracts/crossplane.md): each local service's
// run cost beside the coding sessions on this machine that built it, the same
// checkout the service reports, or another checkout of its repository.
// Node-local data only: nothing here leaves the machine.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { Cable, ChevronDown, ChevronRight } from "lucide-react";
import { Card, ChartShell, DataTable, ErrorState, Icon, InlineEmpty, InlineLoading, Pill, ToolBadge, TooltipSpan } from "@/components/primitives";
import { BuildRunChart, type BuildRunPoint } from "@shared/charts/BuildRunChart";
import { PlaneAMoney } from "@shared/components/planea/money";
import { compact, dateTime } from "@shared/lib/displayFormat";
import type { Tone } from "@shared/lib/tone";
import { useApi } from "@/lib/useApi";

type LinkState = "linked" | "no_match" | "no_signal";

interface LocalProject {
  root: string;
  name: string;
  rule: "project_root" | "repository";
}

interface LocalSession {
  session_id: string;
  tool: string;
  project_root: string;
  started_at: string;
  ended_at?: string;
  cost_usd: number;
  tokens: number;
}

interface LocalService {
  service: string;
  link_state: LinkState;
  traces: number;
  error_traces: number;
  run_cost_usd: number;
  run_tokens: number;
  build_cost_usd: number;
  build_tokens: number;
  projects: LocalProject[];
  sessions: LocalSession[];
  series: BuildRunPoint[];
}

interface ServicesCoding {
  window_days: number;
  available: boolean;
  truncated: boolean;
  unnamed_traces: number;
  services: LocalService[];
}

// LINK_STATES: one row per link state on this machine.
const LINK_STATES: Record<LinkState, { label: string; tone: Tone; hint: string }> = {
  linked: { label: "Linked", tone: "success", hint: "Coding sessions on this machine ran in this service's checkout or repository." },
  // Neutral, not warn: nothing to act on here (Emphasis rule).
  no_match: {
    label: "No coding sessions here",
    tone: "neutral",
    hint: "The service reports a project folder, but no coding session on this machine ran there.",
  },
  no_signal: {
    label: "No project folder reported",
    tone: "neutral",
    hint: "The service's traces report no project folder, so this machine cannot tell which checkout built it.",
  },
};

const RULES: Record<LocalProject["rule"], string> = {
  project_root: "Same checkout",
  repository: "Same repository, another checkout",
};

export function AppsCrossPlane({ days }: { days: number }) {
  const q = useApi<ServicesCoding>("/api/obs/services/coding", { days }, [days]);
  const [open, setOpen] = useState("");
  const d = q.data;
  return (
    <Card icon={Cable} title="Built on this machine" sub="Each app service's run cost beside the coding sessions on this machine that built it.">
      {q.error ? (
        <ErrorState error={q.error} title="Could not read the services" onRetry={q.reload} />
      ) : !d ? (
        <InlineLoading label="Loading the services..." />
      ) : d.services.length === 0 ? (
        <InlineEmpty icon={Cable} message="No app service sent a trace in the window." />
      ) : (
        <ul className="divide-y divide-line-1">
          {d.services.map((s) => (
            <li key={s.service} className="py-2">
              <button
                type="button"
                className="flex w-full flex-wrap items-center gap-2 text-left text-[12.5px]"
                onClick={() => setOpen(open === s.service ? "" : s.service)}
                aria-expanded={open === s.service}
              >
                <Icon icon={open === s.service ? ChevronDown : ChevronRight} size="xs" className="shrink-0 text-fg-3" />
                <span className="font-medium text-fg-0">{s.service}</span>
                <TooltipSpan content={LINK_STATES[s.link_state].hint}>
                  <Pill variant={LINK_STATES[s.link_state].tone}>{LINK_STATES[s.link_state].label}</Pill>
                </TooltipSpan>
                <span className="ml-auto font-mono text-[12px] text-fg-2">
                  run <PlaneAMoney usd={s.run_cost_usd} tokens={s.run_tokens} /> · build{" "}
                  <PlaneAMoney usd={s.build_cost_usd} tokens={s.build_tokens} />
                </span>
              </button>
              {open === s.service && <ServiceBody service={s} />}
            </li>
          ))}
        </ul>
      )}
      {d && !d.available && (
        <p className="mt-2 text-caption text-fg-3">This machine's coding sessions are not linked in this build.</p>
      )}
      {d && d.unnamed_traces > 0 && (
        <p className="mt-2 text-caption text-fg-3">{compact(d.unnamed_traces)} traces named no service and are not linked.</p>
      )}
    </Card>
  );
}

// The coding sessions that built a service: the shared DataTable, the tool
// as its mark, the session linking to the coding Sessions drawer.
function useSessionColumns(): ColumnDef<LocalSession, any>[] {
  return useMemo<ColumnDef<LocalSession, any>[]>(
    () => [
      {
        accessorKey: "session_id",
        header: "Session",
        cell: (c) => (
          <Link className="font-mono text-[11.5px] text-accent hover:underline" to={`/sessions?session=${encodeURIComponent(c.row.original.session_id)}`}>
            {c.row.original.session_id.slice(0, 12)}
          </Link>
        ),
      },
      { accessorKey: "tool", header: "Tool", cell: (c) => <ToolBadge tool={c.row.original.tool} /> },
      { accessorKey: "started_at", header: "Started", cell: (c) => (c.row.original.started_at ? dateTime(c.row.original.started_at) : "-"), meta: { align: "right" } },
      {
        accessorKey: "cost_usd",
        header: "Spend",
        cell: (c) => <PlaneAMoney usd={c.row.original.cost_usd} tokens={c.row.original.tokens} />,
        meta: { align: "right", mono: true },
      },
    ],
    [],
  );
}

function ServiceBody({ service }: { service: LocalService }) {
  const sessionColumns = useSessionColumns();
  return (
    <div className="mt-3 space-y-3">
      <ChartShell title="Build vs run" sub="Per UTC day">
        <BuildRunChart points={service.series} height={180} />
      </ChartShell>
      {service.projects.length > 0 && (
        <ul className="space-y-1 text-[12px]">
          {service.projects.map((p) => (
            <li key={p.root} className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-fg-1">{p.name}</span>
              <span className="min-w-0 break-all font-mono text-fg-3">{p.root}</span>
              <Pill variant="neutral">{RULES[p.rule] ?? p.rule}</Pill>
            </li>
          ))}
        </ul>
      )}
      {service.sessions.length === 0 ? (
        <InlineEmpty icon={Cable} message="No coding session on these projects in the window." />
      ) : (
        <DataTable data={service.sessions} columns={sessionColumns} rowKey={(r) => r.session_id} zebra minWidth={480} />
      )}
    </div>
  );
}
