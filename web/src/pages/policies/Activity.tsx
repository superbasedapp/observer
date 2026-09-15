import { useState } from "react";
import { Link } from "react-router-dom";
import { Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fmtClock } from "@/lib/format";
import { decisionVariant, severityVariant } from "./types";
import { Card, Muted, Select } from "./ui";

// Activity tab — the read-side audit surfaces that close the author → test →
// observe loop inside the Policies module: the admission VERDICT timeline (every
// shadow/enforce decision the policy recorded) and a compact view of the recent
// egress ROUTING decisions. Both are node-local audit logs (never pushed). The
// full egress decision detail lives on the Egress page; this is the quick glance
// right next to where the policy was authored.

type Verdict = {
  id: number;
  ts: string;
  mode: string;
  decision: string;
  severity: string;
  criterion_id: string;
  judge_used: boolean;
  degraded: string;
  latency_ms: number;
  user: string;
  request_id: string;
  reason_excerpt?: string;
};

type EgressDecisionRow = {
  id: number;
  ts: string;
  mode: string;
  rule_name: string;
  action: string;
  upstream_id?: string;
  model_to?: string;
  effort?: string;
  reason_code: string;
  applied: boolean;
  realized_outcome?: string;
  verdict_decision?: string;
  user?: string;
};

const WINDOWS = [
  { value: "1", label: "1h" },
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
];
const DECISION_FILTER = [
  { value: "", label: "all decisions" },
  { value: "allow", label: "allow" },
  { value: "flag", label: "flag" },
  { value: "ask", label: "ask" },
  { value: "deny", label: "deny" },
];

export function ActivityTab() {
  const [win, setWin] = useState("24");
  const [decision, setDecision] = useState("");

  const verdicts = useApi<Verdict[]>("/api/obs/admission/verdicts", { win, decision, limit: 200 }, [win, decision]);
  const egress = useApi<{ decisions: EgressDecisionRow[] | null }>("/api/obs/egress/decisions", { limit: 50 });

  const rows = verdicts.data ?? [];
  const egRows = egress.data?.decisions ?? [];

  return (
    <div className="space-y-4">
      <Card
        title="Admission verdicts"
        sub="Every decision the admission policy recorded - the shadow (observe) or enforced verdict, which criterion fired, and whether the judge ran. Node-local audit; never pushed."
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Select value={win} onChange={setWin} options={WINDOWS} />
          <Select value={decision} onChange={setDecision} options={DECISION_FILTER} />
          <button type="button" onClick={() => verdicts.reload()} className="rounded-2 border border-line-2 px-2 py-1 text-[11px] text-fg-2 hover:text-fg-1">
            Refresh
          </button>
          <span className="text-[11px] text-fg-3">{rows.length} in window</span>
        </div>

        {verdicts.loading && rows.length === 0 ? (
          <Muted>Loading…</Muted>
        ) : rows.length === 0 ? (
          <Muted>No verdicts recorded in this window. Run a request through the app (or the Test tab, which records nothing).</Muted>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">Time</th>
                  <th className="py-1.5 pr-3 font-semibold">Decision</th>
                  <th className="py-1.5 pr-3 font-semibold">Criterion</th>
                  <th className="py-1.5 pr-3 font-semibold">Judge</th>
                  <th className="py-1.5 pr-3 font-semibold">End-user</th>
                  <th className="py-1.5 font-semibold">Reason</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((v) => (
                  <tr key={v.id} className="border-b border-line-1/60 align-top">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">{fmtClock(v.ts)}</td>
                    <td className="py-1.5 pr-3">
                      <span className="inline-flex items-center gap-1">
                        <Pill variant={decisionVariant(v.decision)}>{v.decision}</Pill>
                        {v.severity && v.severity !== "info" && <Pill variant={severityVariant(v.severity)}>{v.severity}</Pill>}
                        {v.mode === "observe" && v.decision !== "allow" && (
                          <span className="text-[10px] text-fg-3" title="observe mode - recorded but not enforced">shadow</span>
                        )}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">{v.criterion_id || "-"}</td>
                    <td className="py-1.5 pr-3">
                      {v.judge_used ? (
                        <span className="text-fg-3">{v.latency_ms}ms{v.degraded ? " · degraded" : ""}</span>
                      ) : (
                        <span className="text-fg-3">deterministic</span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-3">{v.user || "-"}</td>
                    <td className="py-1.5 text-fg-3">{v.reason_excerpt || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title={
          <span className="inline-flex w-full items-center justify-between gap-2">
            <span>Recent egress decisions</span>
            <Link to="/egress" className="text-[11px] font-medium text-accent hover:underline">Full audit on Egress →</Link>
          </span>
        }
        sub="Routing directives the egress policy produced. Advise-mode rows are recorded but never routed; enforce rows carry the proxy's realized outcome."
      >
        {egress.loading && egRows.length === 0 ? (
          <Muted>Loading…</Muted>
        ) : egRows.length === 0 ? (
          <Muted>No egress decisions yet - a row appears when an admission-judged request matches a routing rule.</Muted>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">Time</th>
                  <th className="py-1.5 pr-3 font-semibold">Rule</th>
                  <th className="py-1.5 pr-3 font-semibold">Action</th>
                  <th className="py-1.5 pr-3 font-semibold">Verdict</th>
                  <th className="py-1.5 font-semibold">Realized</th>
                </tr>
              </thead>
              <tbody>
                {egRows.map((d) => (
                  <tr key={d.id} className="border-b border-line-1/60">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">{fmtClock(d.ts)}</td>
                    <td className="py-1.5 pr-3 font-semibold text-fg-1">{d.rule_name}</td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">
                      {d.action}
                      {egressActionDetail(d) && <span className="text-fg-3"> {egressActionDetail(d)}</span>}
                    </td>
                    <td className="py-1.5 pr-3">
                      {d.verdict_decision ? <Pill variant={decisionVariant(d.verdict_decision)}>{d.verdict_decision}</Pill> : <span className="text-fg-3">-</span>}
                    </td>
                    <td className="py-1.5">
                      {d.realized_outcome ? (
                        <Pill variant={d.realized_outcome === "applied" ? "success" : d.realized_outcome.includes("open") || d.realized_outcome.includes("error") ? "danger" : "neutral"}>
                          {d.realized_outcome}
                        </Pill>
                      ) : (
                        <span className="text-fg-3" title="advise-mode decisions are recorded but never routed">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function egressActionDetail(d: EgressDecisionRow): string {
  if (d.upstream_id) return `→ ${d.upstream_id}`;
  if (d.model_to) return `→ ${d.model_to}`;
  if (d.effort) return `→ ${d.effort}`;
  return "";
}
